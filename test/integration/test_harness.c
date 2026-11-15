/*
 * Integration test harness for lurch OMEMO plugin.
 *
 * Runs a headless libpurple instance with XMPP accounts connected to a
 * local Prosody server, loads the lurch and carbons plugins, and runs
 * one scenario: a named sequence of test phases (see the registry in
 * test_phases.c). run.sh gives each scenario a fresh Prosody container,
 * so scenarios don't share server state.
 *
 * Phases assert both on what the clients observe (delivery, plaintext
 * absent from the wire, lurch API results) and on what the server
 * stores (PEP devicelist contents, via test_server.c).
 *
 * Usage: ./test_integration [--scenario NAME] path/to/lurch.so [path/to/carbons.so]
 *        ./test_integration --list
 */

#include "test_harness.h"

TestState S = {0};

/* ================================================================
 * Helpers
 * ================================================================ */

/* Logs an individual passing assertion and bumps the suite tally.
 * Phases call this once per logical sub-check so the final tally
 * counts assertions, not phases. */
void test_pass(const char *name) {
    fprintf(stderr, "  PASS  %s\n", name);
    S.tests_passed++;
}

/* Same idea for a failing assertion; the reason string is meant to
 * give enough context to diagnose without re-running with debug logs. */
void test_fail(const char *name, const char *reason) {
    fprintf(stderr, "  FAIL  %s — %s\n", name, reason);
    S.tests_failed++;
}

/* Wipes the sent-text accumulator and any pending wait between phases
 * (and between sub-steps within a phase that re-arms a wait). */
void reset_phase_counters(void) {
    g_free(S.sent_text);
    S.sent_text = NULL;
    S.sent_msg_count = 0;
    S.sent_encrypted = FALSE;

    if (S.wait.timeout_id) {
        g_source_remove(S.wait.timeout_id);
        S.wait.timeout_id = 0;
    }
    S.wait.recv = NULL;
    S.wait.expected_text = NULL;
    S.wait.wanted = 0;
    S.wait.got = 0;
    S.wait.on_done = NULL;
}

/* Phases are dispatched on a GLib timer rather than chained directly so
 * libpurple has cycles to flush its outgoing-stanza queue and deliver
 * incoming messages before the next phase observes them. */
void next_phase(void) {
    S.phase++;
    reset_phase_counters();
    g_timeout_add(PHASE_DELAY_MS, run_phase, NULL);
}

/* libpurple won't let you send into an IM that doesn't have a conversation
 * object yet — find-or-create handles both the first send and subsequent
 * ones uniformly. */
PurpleConversation *send_im(PurpleAccount *from, const char *to, const char *msg) {
    PurpleConversation *conv = purple_find_conversation_with_account(
        PURPLE_CONV_TYPE_IM, to, from);
    if (!conv) {
        conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, from, to);
    }
    if (!conv) {
        fprintf(stderr, "[harness] ERROR: failed to create conversation to %s\n", to);
        return NULL;
    }
    purple_conv_im_send(PURPLE_CONV_IM(conv), msg);
    return conv;
}

/* Fires the wait's on_done callback exactly once. Triggered by either
 * conv_write_im (on an incoming match reaching `wanted`) or the
 * fallback timer. We use on_done==NULL as the "already fired" guard:
 * the cb pointer is nulled when we take it, so re-entry no-ops.
 * Deferred via g_idle_add so on_done runs at top level rather than
 * nested inside whatever signal handler reached the trigger. */
static void fire_completion(void) {
    if (!S.wait.on_done) {
        return;
    }
    if (S.wait.timeout_id) {
        g_source_remove(S.wait.timeout_id);
        S.wait.timeout_id = 0;
    }
    GSourceFunc fn = S.wait.on_done;
    S.wait.on_done = NULL;
    g_idle_add(fn, NULL);
}

/* Fallback-timeout source. If the expected event never arrives, the
 * phase still runs and inspects the snapshot/wait as they stood at the
 * deadline — that produces a meaningful test failure rather than a
 * silent hang. */
static gboolean completion_timeout_cb(gpointer data) {
    (void) data;
    fprintf(stderr, "[harness] wait timeout — expected event never observed\n");
    S.wait.timeout_id = 0;
    fire_completion();
    return FALSE;
}

/* Arms S.wait with the supplied callback + fallback timer. The wait's
 * recv / expected_text / wanted must already be set by the caller. */
static void arm_wait(GSourceFunc on_done, guint timeout_ms) {
    if (S.wait.timeout_id) {
        g_source_remove(S.wait.timeout_id);
    }
    S.wait.on_done = on_done;
    S.wait.timeout_id = g_timeout_add(timeout_ms, completion_timeout_cb, NULL);
}

/* Arms S.wait for `count` matching arrivals at `recv`. The phase
 * does the corresponding sends itself, after this call (so a fast
 * local echo doesn't race the arming). */
void await_messages(PurpleAccount *recv, const char *expected_text,
                    int count, GSourceFunc on_done, guint timeout_ms) {
    S.wait.recv = recv;
    S.wait.expected_text = expected_text;
    S.wait.wanted = count;
    S.wait.got = 0;
    arm_wait(on_done, timeout_ms);
}

/* Prints the final tally and breaks out of the main loop. Called once
 * after the last phase completes or on test timeout. Asserts that the
 * scenario actually ran all its phases — without this, a run where the
 * accounts never connect (and thus no phase ever executes) would exit
 * with zero failures and report a false pass. */
void finish_tests(void) {
    int n_phases = S.scenario ? S.scenario->n_phases : 0;
    if (S.phases_started && S.phase >= n_phases) {
        test_pass("all test phases completed");
    } else {
        char reason[96];
        snprintf(reason, sizeof(reason), "scenario ended in phase %d of %d%s",
                 S.phase, n_phases, S.phases_started ? "" : " (phases never started)");
        test_fail("all test phases completed", reason);
    }

    fprintf(stderr, "\n========================================\n");
    fprintf(stderr, "Results: %d passed, %d failed\n\n",
            S.tests_passed, S.tests_failed);
    g_main_loop_quit(S.loop);
}

/* Callback for lurch-id-list. lurch puts the own device ID first in
 * the list (and returns an empty list if its own ID is missing from
 * the cached devicelist). Fires synchronously inside purple_signal_emit. */
static void own_id_cb(int32_t err, GList *id_list, void *user_data) {
    uint32_t *out = user_data;
    if (err == 0 && id_list) {
        *out = *(uint32_t *) id_list->data;
    }
}

/* Returns the account's own OMEMO device ID, or 0 if lurch doesn't
 * report one. */
uint32_t own_device_id(PurpleAccount *acc) {
    uint32_t id = 0;
    purple_signal_emit(purple_plugins_get_handle(), "lurch-id-list",
                       acc, own_id_cb, &id);
    fprintf(stderr, "[harness] own device ID of %s: %u\n",
            purple_account_get_username(acc), id);
    return id;
}

/* ================================================================
 * GLib-backed libpurple event loop
 * ================================================================ */

typedef struct {
    PurpleInputFunction func;
    gpointer            data;
} GLibIOClosure;

/* libpurple expects a host application to provide its own I/O watchers
 * (PurpleEventLoopUiOps). This file adapts GLib's GIOChannel watchers
 * to libpurple's PurpleInputFunction signature so we can run a purple
 * core on top of an ordinary GMainLoop. */
static gboolean glib_io_invoke(GIOChannel *src, GIOCondition cond, gpointer data) {
    GLibIOClosure *closure = data;
    PurpleInputCondition pc = 0;

    if (cond & (G_IO_IN  | G_IO_HUP | G_IO_ERR)) {
        pc |= PURPLE_INPUT_READ;
    }
    if (cond & (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
        pc |= PURPLE_INPUT_WRITE;
    }

    closure->func(closure->data, g_io_channel_unix_get_fd(src), pc);
    return TRUE;
}

/* The "add an fd watcher" half of the libpurple↔GLib bridge: wraps a
 * libpurple PurpleInputFunction in a GIOChannel watch and returns the
 * GLib source ID so libpurple can later remove it via g_source_remove. */
static guint glib_input_add(gint fd, PurpleInputCondition cond,
                            PurpleInputFunction func, gpointer data) {
    GLibIOClosure *closure = g_new0(GLibIOClosure, 1);
    GIOCondition gc = 0;

    closure->func = func;
    closure->data = data;

    if (cond & PURPLE_INPUT_READ) {
        gc |= G_IO_IN | G_IO_HUP | G_IO_ERR;
    }
    if (cond & PURPLE_INPUT_WRITE) {
        gc |= G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
    }

    GIOChannel *channel = g_io_channel_unix_new(fd);
    guint id = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT, gc,
                                   glib_io_invoke, closure, g_free);
    g_io_channel_unref(channel);
    return id;
}

static PurpleEventLoopUiOps eventloop_uiops = {
    g_timeout_add,
    g_source_remove,
    glib_input_add,
    g_source_remove,
    NULL,                   /* input_get_error */
    g_timeout_add_seconds,
    NULL, NULL, NULL
};

/* ================================================================
 * Conversation UI ops — captures messages
 * ================================================================ */

/* Logged so the test transcript shows when libpurple first
 * materialised an IM conversation for each direction — useful when
 * diagnosing "message was sent but never delivered" failures. */
static void conv_create(PurpleConversation *conv) {
    fprintf(stderr, "[harness] conversation created: %s (account: %s)\n",
            purple_conversation_get_name(conv),
            purple_account_get_username(purple_conversation_get_account(conv)));
}

/* libpurple's "an IM was written to the UI" hook — fires for both
 * outgoing and incoming directions. This is the harness's primary
 * delivery signal: when an incoming message on the expected account
 * matches the expected text, we bump S.wait.got (and fire the wait's
 * completion once it reaches the wanted count). */
static void conv_write_im(PurpleConversation *conv, const char *who,
                           const char *message, PurpleMessageFlags flags,
                           time_t mtime) {
    PurpleAccount *acc = purple_conversation_get_account(conv);

    fprintf(stderr, "[harness] write_im: account=%s who=%s flags=0x%x msg='%.80s'\n",
            purple_account_get_username(acc),
            who ? who : "(null)", flags,
            message ? message : "(null)");

    /* Only count incoming messages for the expected receiver */
    if (S.wait.recv && acc == S.wait.recv &&
        !(flags & PURPLE_MESSAGE_SEND) && message &&
        S.wait.expected_text && strstr(message, S.wait.expected_text)) {
        S.wait.got++;
        fprintf(stderr, "[harness] *** correct message received (#%d) ***\n",
                S.wait.got);
        if (S.wait.wanted > 0 && S.wait.got >= S.wait.wanted) {
            fire_completion();
        }
    }
}

/* The "system / status message" hook — libpurple uses this for things
 * like "user is typing" and connection errors. We only log it to keep
 * the transcript complete; nothing in the test assertions consumes it. */
static void conv_write_conv(PurpleConversation *conv, const char *name,
                             const char *alias, const char *message,
                             PurpleMessageFlags flags, time_t mtime) {
    fprintf(stderr, "[harness] write_conv: %s: %s\n",
            name ? name : "(null)", message ? message : "(null)");
}

static PurpleConversationUiOps conv_uiops = {
    conv_create,        /* create_conversation */
    NULL,               /* destroy_conversation */
    NULL,               /* write_chat */
    conv_write_im,      /* write_im */
    conv_write_conv,    /* write_conv */
    NULL,               /* chat_add_users */
    NULL,               /* chat_rename_user */
    NULL,               /* chat_remove_users */
    NULL,               /* chat_update_user */
    NULL,               /* present */
    NULL,               /* has_focus */
    NULL,               /* custom_smiley_add */
    NULL,               /* custom_smiley_write */
    NULL,               /* custom_smiley_close */
    NULL,               /* send_confirm */
    NULL, NULL, NULL, NULL
};

/* ================================================================
 * XML capture — hooks into jabber-{sending,receiving}-xmlnode
 *
 * jabber-sending-xmlnode runs AFTER lurch has processed the stanza
 * (lurch uses a very high priority), so we see the encrypted result.
 * ================================================================ */

/* Single canonical "[harness] <label> for <user>:\n<xml>" format used by
 * both directions of XML capture. Centralising keeps log output greppable
 * when diagnosing failures across many phases. */
static void log_stanza(PurpleAccount *acc, xmlnode *stanza, const char *label) {
    char *xml_str = xmlnode_to_str(stanza, NULL);
    if (!xml_str) {
        return;
    }
    fprintf(stderr, "[harness] %s for %s:\n%s\n",
            label, purple_account_get_username(acc), xml_str);
    g_free(xml_str);
}

/* Returns TRUE if the stanza is a PEP headline notification for the
 * OMEMO devicelist node — the observable proof that a devicelist
 * publish (or update) completed its round-trip through the server.
 * Shared by the parent's orchestration triggers and the child's READY
 * detection so the wire format is parsed in exactly one place. */
static gboolean stanza_is_devicelist_event(xmlnode *stanza) {
    if (!stanza->name || strcmp(stanza->name, "message") != 0) {
        return FALSE;
    }
    const char *type = xmlnode_get_attrib(stanza, "type");
    if (!type || strcmp(type, "headline") != 0) {
        return FALSE;
    }
    xmlnode *event = xmlnode_get_child_with_namespace(
        stanza, "event", "http://jabber.org/protocol/pubsub#event");
    if (!event) {
        return FALSE;
    }
    xmlnode *items = xmlnode_get_child(event, "items");
    if (!items) {
        return FALSE;
    }
    const char *node = xmlnode_get_attrib(items, "node");
    return node && strcmp(node, OMEMO_NS ".devicelist") == 0;
}

static gboolean connect_alice(gpointer data);
static void start_phases(const char *reason);

/* Returns the device IDs (uint32_t *) listed in a devicelist PEP event
 * stanza, in document order; NULL if it lists none. */
static GList *devicelist_event_ids(xmlnode *stanza) {
    xmlnode *event = xmlnode_get_child_with_namespace(
        stanza, "event", "http://jabber.org/protocol/pubsub#event");
    xmlnode *items = event ? xmlnode_get_child(event, "items") : NULL;
    xmlnode *item = items ? xmlnode_get_child(items, "item") : NULL;
    xmlnode *list = item ? xmlnode_get_child_with_namespace(item, "list", OMEMO_NS) : NULL;

    GList *ids = NULL;
    for (xmlnode *dev = list ? xmlnode_get_child(list, "device") : NULL; dev;
         dev = xmlnode_get_next_twin(dev)) {
        const char *id_str = xmlnode_get_attrib(dev, "id");
        if (!id_str) {
            continue;
        }
        uint32_t *id = g_new(uint32_t, 1);
        *id = (uint32_t) g_ascii_strtoull(id_str, NULL, 10);
        ids = g_list_append(ids, id);
    }
    return ids;
}

/* Returns TRUE if `ids` (a uint32_t * list) contains `id`. */
static gboolean id_list_contains(GList *ids, uint32_t id) {
    for (GList *l = ids; l; l = l->next) {
        if (*(uint32_t *) l->data == id) {
            return TRUE;
        }
    }
    return FALSE;
}

/* Stores the device IDs from a devicelist event alice received from
 * bob (replacing the previous one) and bumps the event counter. lurch
 * handles the same stanza right after this signal, so by the next main
 * loop iteration its cache reflects it too. */
static void record_alice_bob_devicelist(xmlnode *stanza) {
    g_list_free_full(S.alice_bob_dl_ids, g_free);
    S.alice_bob_dl_ids = devicelist_event_ids(stanza);
    S.alice_bob_dl_events++;
    fprintf(stderr, "[harness] alice got bob's devicelist event #%d (%u devices)\n",
            S.alice_bob_dl_events, g_list_length(S.alice_bob_dl_ids));
}

/* Returns TRUE if the most recent devicelist event alice received from
 * bob lists `id`. */
gboolean alice_saw_bob_device(uint32_t id) {
    return id_list_contains(S.alice_bob_dl_ids, id);
}

/* Logs incoming IQ and PEP-headline message stanzas to aid debugging of
 * OMEMO bundle/devicelist exchanges, and drives the two event-based
 * orchestration triggers: bob's own devicelist echo means his publish
 * settled (safe to connect alice), and alice observing bob's devicelist
 * means the OMEMO precondition for messaging is met (safe to start the
 * phases). Wall-clock timers exist only as fallbacks for both. */
static void xml_recv_cb(PurpleConnection *gc, xmlnode **stanza_pp) {
    if (!stanza_pp || !*stanza_pp) {
        return;
    }

    xmlnode *stanza = *stanza_pp;
    const char *name = stanza->name;
    if (!name) {
        return;
    }

    PurpleAccount *acc = purple_connection_get_account(gc);

    if (strcmp(name, "iq") == 0) {
        log_stanza(acc, stanza, "incoming IQ");
        return;
    }

    if (strcmp(name, "message") != 0) {
        return;
    }

    const char *type = xmlnode_get_attrib(stanza, "type");
    if (!type || strcmp(type, "headline") != 0) {
        return;
    }

    log_stanza(acc, stanza, "incoming PEP event");

    if (!stanza_is_devicelist_event(stanza)) {
        return;
    }

    const char *from = xmlnode_get_attrib(stanza, "from");
    if (acc == S.alice && from && strcmp(from, BOB_JID "@" XMPP_SERVER) == 0) {
        record_alice_bob_devicelist(stanza);
    }

    if (acc == S.bob && !S.alice) {
        /* Bob's publish round-trip completed — bring alice up now
         * instead of waiting out the fallback timer. */
        g_timeout_add(500, connect_alice, NULL);
    } else if (acc == S.alice && !S.phases_started &&
               from && strcmp(from, BOB_JID "@" XMPP_SERVER) == 0) {
        start_phases("alice observed bob's devicelist");
    }
}

/* Walks every tag node in the stanza tree and appends each node's
 * direct text content to `buf`. Used to build S.sent_text — a single
 * string the phase check can grep for the plaintext message. Catches
 * <body> leaks, <html><body> (XEP-0071) leaks, and any future
 * markup-bearing element that grows up in libpurple. */
static void collect_text_recursive(xmlnode *node, GString *buf) {
    if (!node) {
        return;
    }
    char *data = xmlnode_get_data(node);
    if (data) {
        g_string_append(buf, data);
        g_string_append_c(buf, '\n');
        g_free(data);
    }
    for (xmlnode *c = node->child; c; c = c->next) {
        if (c->type == XMLNODE_TYPE_TAG) {
            collect_text_recursive(c, buf);
        }
    }
}

/* Outgoing XML hook. Connected with PRIORITY_HIGHEST so it fires AFTER
 * lurch has transformed the stanza — what we see here is the final
 * wire form. The only structural inspection is recursive text
 * collection: every text node in the stanza is appended to S.sent_text
 * so the phase check can grep it for the plaintext message it asked
 * lurch to send (absent ⇒ encrypted; present ⇒ plaintext on the wire). */
static void xml_sent_cb(PurpleConnection *gc, xmlnode **stanza_pp) {
    if (!stanza_pp || !*stanza_pp) {
        return;
    }

    xmlnode *stanza = *stanza_pp;
    const char *name = stanza->name;
    if (!name) {
        return;
    }

    PurpleAccount *acc = purple_connection_get_account(gc);

    if (strcmp(name, "iq") == 0) {
        log_stanza(acc, stanza, "outgoing IQ");
        return;
    }

    if (strcmp(name, "message") != 0) {
        return;
    }
    if (!xmlnode_get_attrib(stanza, "to")) {
        return;
    }

    log_stanza(acc, stanza, "outgoing message");

    /* Track that a message stanza actually left, and whether it carried
     * an OMEMO payload — plaintext absence alone can't distinguish
     * "encrypted" from "never sent". */
    S.sent_msg_count++;
    if (xmlnode_get_child_with_namespace(stanza, "encrypted", OMEMO_NS)) {
        S.sent_encrypted = TRUE;
    }

    /* Append this stanza's text content to the phase-wide accumulator. */
    GString *buf = g_string_new(S.sent_text ? S.sent_text : "");
    collect_text_recursive(stanza, buf);
    g_free(S.sent_text);
    S.sent_text = g_string_free(buf, FALSE);
}

/* ================================================================
 * Account status callbacks
 * ================================================================ */

/* Deferred alice-connect: fired either by bob's devicelist PEP echo
 * (the event-driven path in xml_recv_cb) or by the wall-clock fallback
 * armed in account_signed_on — whichever comes first; the S.alice
 * latch makes the second trigger a no-op. Connecting alice too early
 * can cause her to miss bob's devicelist subscription and fail
 * subsequent OMEMO operations. */
static gboolean connect_alice(gpointer data) {
    (void) data;
    if (S.alice) {
        return FALSE;   /* the other trigger already connected her */
    }
    fprintf(stderr, "[harness] connecting alice...\n");
    S.alice = create_account(ALICE_JID, ALICE_PASS);
    return FALSE;
}

/* One-shot entry into the phase machine, fired either by alice
 * observing bob's devicelist PEP event (the real precondition for
 * OMEMO messaging) or by the SEND_DELAY_MS fallback timer. The short
 * settle delay lets caps/subscription traffic finish before phase 1
 * sends. */
static void start_phases(const char *reason) {
    if (S.phases_started) {
        return;
    }
    S.phases_started = TRUE;
    fprintf(stderr, "[harness] starting scenario '%s' (%s)...\n",
            S.scenario->name, reason);

    /* Starting via the fallback timer would hide a missing devicelist
     * event, so its arrival is asserted rather than just awaited. */
    if (S.alice_bob_dl_events > 0) {
        test_pass("startup: alice received bob's devicelist");
    } else {
        test_fail("startup: alice received bob's devicelist",
                  "no devicelist event from bob reached alice; phases started by fallback timer");
    }
    S.phase = 0;
    reset_phase_counters();
    g_timeout_add(1000, run_phase, NULL);
}

/* GSourceFunc-shaped adapter so start_phases can sit on the fallback
 * timer armed when alice signs on. */
static gboolean start_phases_fallback(gpointer data) {
    (void) data;
    start_phases("fallback timer");
    return FALSE;
}

/* Connection orchestration. Bob comes online first (so his PEP nodes
 * are published before alice subscribes); on bob's first signed-on
 * event we arm the alice-connect fallback, and on alice's we arm the
 * phase-start fallback — the event-driven triggers in xml_recv_cb
 * usually beat both. The bob_reconnecting flag suppresses the
 * alice-connect path when bob is just re-signing on for the
 * reconnect phase. */
static void account_signed_on(PurpleAccount *account) {
    const char *user = purple_account_get_username(account);
    fprintf(stderr, "[harness] account signed on: %s\n", user);

    if (account == S.bob) {
        S.bob_connected = TRUE;

        if (S.bob_reconnecting) {
            S.bob_reconnecting = FALSE;
            fprintf(stderr, "[harness] bob reconnected.\n");
            return;
        }

        /* Fallback in case bob's devicelist echo never arrives */
        g_timeout_add(3000, connect_alice, NULL);
    } else if (account == S.alice) {
        S.alice_connected = TRUE;
        fprintf(stderr, "[harness] both accounts online, starting tests "
                        "(fallback in %d ms)...\n", SEND_DELAY_MS);
        g_timeout_add(SEND_DELAY_MS, start_phases_fallback, NULL);
    }
}

/* Mirror of account_signed_on for disconnects. Only updates the
 * connected flags; the reconnect-phase logic polls those rather
 * than reacting to this signal directly. */
static void account_signed_off(PurpleAccount *account) {
    const char *user = purple_account_get_username(account);
    fprintf(stderr, "[harness] account signed off: %s\n", user);

    if (account == S.bob) {
        S.bob_connected = FALSE;
    } else if (account == S.alice) {
        S.alice_connected = FALSE;
    }
}

/* ================================================================
 * Test timeout
 * ================================================================ */

/* Suite-wide deadline. If something hangs (PEP never arrives, libpurple
 * deadlocks, etc.) this fires after TEST_TIMEOUT_S seconds and forces
 * a clean shutdown so CI doesn't sit forever. */
static gboolean test_timeout(gpointer data) {
    (void) data;
    fprintf(stderr, "\n[harness] TEST TIMEOUT after %d seconds (phase=%d)\n",
            TEST_TIMEOUT_S, S.phase);
    finish_tests();
    return FALSE;
}

/* ================================================================
 * libpurple initialization
 * ================================================================ */

/* Both the parent harness and the forked second-device child need the
 * same libpurple bring-up sequence, only differing in user dir and the
 * conversation UI ops they install. Factored out to keep the two call
 * sites in sync. */
static int purple_minimal_init(const char *user_dir, PurpleConversationUiOps *conv_ops) {
    purple_util_set_user_dir(user_dir);
    purple_eventloop_set_ui_ops(&eventloop_uiops);
    purple_conversations_set_ui_ops(conv_ops);
    purple_debug_set_enabled(getenv("PURPLE_DEBUG") != NULL);

    if (!purple_core_init("lurch-integration-test")) {
        fprintf(stderr, "ERROR: purple_core_init failed\n");
        return -1;
    }

    purple_set_blist(purple_blist_new());
    purple_blist_load();
    purple_prefs_load();
    return 0;
}

/* Both the lurch and (optional) carbons plugins are loaded the same way:
 * probe, load, log. Wrapping it gives consistent error messages and
 * makes the call sites read as a checklist. */
static PurplePlugin *load_plugin(const char *path) {
    PurplePlugin *plugin = purple_plugin_probe(path);
    if (!plugin) {
        fprintf(stderr, "ERROR: purple_plugin_probe failed for %s\n", path);
        return NULL;
    }

    if (!purple_plugin_load(plugin)) {
        fprintf(stderr, "ERROR: purple_plugin_load failed for %s\n", path);
        return NULL;
    }

    fprintf(stderr, "plugin loaded: %s\n", purple_plugin_get_name(plugin));
    return plugin;
}

/* Bundles JID construction with the test-specific account prefs
 * (no TLS, configurable port, auto-enable). Used by the parent for
 * alice/bob and by the child for its second bob device. */
PurpleAccount *create_account(const char *user, const char *pass) {
    char jid[256];
    snprintf(jid, sizeof(jid), "%s@%s", user, XMPP_SERVER);

    PurpleAccount *acc = purple_account_new(jid, JABBER_PROTOCOL_ID);
    purple_account_set_password(acc, pass);

    purple_account_set_bool(acc, "require_tls", FALSE);
    purple_account_set_remember_password(acc, TRUE);
    const char *port_str = getenv("XMPP_PORT");
    int port = (port_str && atoi(port_str)) ? atoi(port_str) : XMPP_PORT_DEFAULT;
    purple_account_set_int(acc, "port", port);

    purple_account_set_enabled(acc, "lurch-integration-test", TRUE);

    fprintf(stderr, "account created and enabled: %s\n", jid);
    return acc;
}

/* The outgoing hook uses PURPLE_SIGNAL_PRIORITY_HIGHEST so it runs AFTER
 * lurch has had a chance to transform the stanza — otherwise we'd see
 * the plaintext stanza before encryption and the OMEMO assertions would
 * never fire. */
static void connect_xml_signals(void) {
    void *jabber_handle = purple_plugins_find_with_id(JABBER_PROTOCOL_ID);
    if (!jabber_handle) {
        fprintf(stderr, "[harness] WARNING: jabber plugin not found, "
                        "cannot capture XML\n");
        return;
    }

    purple_signal_connect_priority(jabber_handle, "jabber-sending-xmlnode",
                          &S, PURPLE_CALLBACK(xml_sent_cb), NULL,
                          PURPLE_SIGNAL_PRIORITY_HIGHEST);
    purple_signal_connect(jabber_handle, "jabber-receiving-xmlnode",
                          &S, PURPLE_CALLBACK(xml_recv_cb), NULL);

    fprintf(stderr, "[harness] XML capture signals connected\n");
}

/* ================================================================
 * Child process — bob's second device
 *
 * Forked before any libpurple init. Runs its own libpurple with a
 * separate user dir, connects as bob, and waits for a message.
 * Communicates with parent via pipes.
 * ================================================================ */

typedef struct {
    GMainLoop *loop;
    int read_fd;
    int write_fd;
    gboolean msg_received;
    gboolean msg_correct;
    gboolean ready_sent;     /* one-shot guard around the READY write */
    gboolean send_seen;      /* parent has signaled SEND */
    gboolean reported;       /* one-shot guard around the result write */
    PurpleAccount *acc;      /* the second bob device's account (NULL until connected) */
    GList *last_dl_ids;      /* device IDs in the latest own devicelist event */
} ChildState;

static ChildState C = {0};

static gboolean child_report_result(gpointer data);

/* Writes "READY <device id>" up the pipe to the parent exactly once,
 * then sets the latch so subsequent triggers no-op. The device ID lets
 * the parent assert the server-side devicelist without asking again.
 * Triggered either by the server echoing our PEP devicelist publish
 * back (the real precondition) or by a fallback timer that fires
 * regardless (so a missing echo doesn't hang the suite forever). */
static void child_signal_ready(const char *reason) {
    if (C.ready_sent) {
        return;
    }
    C.ready_sent = TRUE;
    uint32_t id = C.acc ? own_device_id(C.acc) : 0;
    fprintf(stderr, "[dev2] signaling READY, device ID %u (%s)\n", id, reason);
    char line[32];
    int len = snprintf(line, sizeof(line), "READY %u\n", id);
    write(C.write_fd, line, len);
}

/* Child-side conv_write_im: equivalent of the parent's hook but for
 * bob's second device. Latches whether the incoming message matches
 * MSG_MULTI_DEV, and — once the parent has signaled SEND — reports
 * the result up the pipe immediately on arrival instead of waiting
 * out a fixed timer. */
static void child_conv_write_im(PurpleConversation *conv, const char *who,
                                 const char *message, PurpleMessageFlags flags,
                                 time_t mtime) {
    PurpleAccount *acc = purple_conversation_get_account(conv);
    fprintf(stderr, "[dev2] write_im: account=%s who=%s flags=0x%x msg='%.80s'\n",
            purple_account_get_username(acc),
            who ? who : "(null)", flags,
            message ? message : "(null)");

    if (!(flags & PURPLE_MESSAGE_SEND) && message) {
        C.msg_received = TRUE;
        if (strstr(message, MSG_MULTI_DEV)) {
            C.msg_correct = TRUE;
            if (C.send_seen) {
                child_report_result(NULL);
            }
        }
    }
}

/* Child-side system message hook; only logs, like its parent twin. */
static void child_conv_write_conv(PurpleConversation *conv, const char *name,
                                   const char *alias, const char *message,
                                   PurpleMessageFlags flags, time_t mtime) {
    fprintf(stderr, "[dev2] write_conv: %s: %s\n",
            name ? name : "(null)", message ? message : "(null)");
}

static PurpleConversationUiOps child_conv_uiops = {
    NULL,                   /* create_conversation */
    NULL,                   /* destroy_conversation */
    NULL,                   /* write_chat */
    child_conv_write_im,    /* write_im */
    child_conv_write_conv,  /* write_conv */
    NULL, NULL, NULL, NULL, /* chat ops */
    NULL,                   /* present */
    NULL,                   /* has_focus */
    NULL, NULL, NULL,       /* custom_smiley */
    NULL,                   /* send_confirm */
    NULL, NULL, NULL, NULL
};

/* Fallback timer: if no PEP echo arrives within the deadline we
 * signal READY anyway. A missing echo means something is wrong
 * server-side, but better to fail fast in the downstream phases
 * than hang the suite at startup. */
static gboolean child_ready_fallback(gpointer data) {
    (void) data;
    child_signal_ready("fallback timeout (no PEP echo)");
    return FALSE;
}

/* Just logs the sign-on and arms the fallback timer. The real READY
 * signal comes from child_xml_recv_cb when the server echoes our
 * devicelist publish — that's the actual precondition the parent
 * needs before its bob can sign in and merge its own device ID. */
static void child_signed_on(PurpleAccount *account) {
    fprintf(stderr, "[dev2] account signed on: %s\n",
            purple_account_get_username(account));
    g_timeout_add(10000, child_ready_fallback, NULL);
}

/* Runs after lurch has handled a devicelist event: signals READY once
 * the event lists our own device ID. An event without it (e.g. the
 * existing list the server delivers at login, when another bob device
 * published first) is not the echo of our publish, so keep waiting. */
static gboolean child_check_own_listed(gpointer data) {
    (void) data;
    if (C.ready_sent || !C.acc) {
        return FALSE;
    }
    uint32_t id = own_device_id(C.acc);
    if (id && id_list_contains(C.last_dl_ids, id)) {
        child_signal_ready("devicelist PEP echo lists own ID");
    }
    return FALSE;
}

/* Watches incoming stanzas for the server echo of our OMEMO
 * devicelist PEP publish; that arrival is the proof that lurch's
 * publish round-trip completed and the parent can safely go on
 * without racing the devicelist. The check is deferred to an idle
 * callback because lurch's own PEP handler runs after this hook. */
static void child_xml_recv_cb(PurpleConnection *gc, xmlnode **stanza_pp) {
    if (C.ready_sent || !stanza_pp || !*stanza_pp) {
        return;
    }
    if (stanza_is_devicelist_event(*stanza_pp)) {
        g_list_free_full(C.last_dl_ids, g_free);
        C.last_dl_ids = devicelist_event_ids(*stanza_pp);
        g_idle_add(child_check_own_listed, NULL);
    }
}

/* Writes the second-device verdict up the pipe exactly once: PASS /
 * "FAIL: wrong content" / "FAIL: no message". Triggered by the message
 * arriving (child_conv_write_im), the post-SEND fallback timer, or a
 * QUIT that arrives while a report is still pending. */
static gboolean child_report_result(gpointer data) {
    (void) data;
    if (C.reported) {
        return FALSE;
    }
    C.reported = TRUE;

    if (C.msg_correct) {
        fprintf(stderr, "[dev2] *** received correct message ***\n");
        write(C.write_fd, "PASS\n", 5);
    } else if (C.msg_received) {
        write(C.write_fd, "FAIL: wrong content\n", 20);
    } else {
        write(C.write_fd, "FAIL: no message\n", 17);
    }
    return FALSE;
}

/* Handles the parent's SEND command. If the message already arrived
 * (a carbon can beat the pipe), report right away; otherwise the
 * report fires from child_conv_write_im on arrival, with a fallback
 * timer so a lost message still produces a FAIL answer instead of
 * silence. */
static void child_handle_send(void) {
    fprintf(stderr, "[dev2] parent signaled SEND, waiting for message...\n");
    C.send_seen = TRUE;
    if (C.msg_correct) {
        child_report_result(NULL);
    } else {
        g_timeout_add(8000, child_report_result, NULL);
    }
}

/* Polled command channel from parent. Commands are newline-framed and
 * can coalesce into a single read, so each line is handled in arrival
 * order — a QUIT that lands together with (or right after) SEND first
 * flushes the pending report so the parent still gets an answer. The
 * pipe is set non-blocking so this can sit on a GLib timer without
 * stalling the child's main loop. */
static void child_connect(void);

static gboolean child_check_parent(gpointer data) {
    (void) data;
    char buf[64] = {0};
    ssize_t n = read(C.read_fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        return TRUE;
    }

    char *saveptr = NULL;
    for (char *line = strtok_r(buf, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        if (strcmp(line, "CONNECT") == 0) {
            child_connect();
        } else if (strcmp(line, "SEND") == 0) {
            child_handle_send();
        } else if (strcmp(line, "QUIT") == 0) {
            if (C.send_seen && !C.reported) {
                child_report_result(NULL);
            }
            g_main_loop_quit(C.loop);
            return FALSE;
        }
    }

    return TRUE;
}

/* GSourceFunc-shaped wrapper for the child's lifetime deadline —
 * casting g_main_loop_quit (which returns void) to GSourceFunc is
 * undefined behavior and leaves the source's repeat behavior to
 * whatever garbage sits in the return register. */
static gboolean quit_loop(gpointer loop) {
    g_main_loop_quit(loop);
    return FALSE;
}

/* Signs the second device in as bob. Runs right away for DEV2_AT_START
 * and on the parent's CONNECT command for DEV2_ON_DEMAND; a second
 * CONNECT is ignored. */
static void child_connect(void) {
    if (C.acc) {
        return;
    }
    fprintf(stderr, "[dev2] connecting...\n");
    C.acc = create_account(BOB_JID, BOB_PASS);
    /* Absolute READY fallback: the 10s timer in child_signed_on never
     * arms if sign-on itself fails, and the parent must not wait on a
     * silent child. */
    g_timeout_add_seconds(30, child_ready_fallback, NULL);
}

/* Entry point of the forked second-device process. Sets up its own
 * libpurple, loads lurch (+ carbons), and enters a GLib loop that talks
 * to the parent over pipes. It signs in as a SECOND bob (same JID,
 * separate user dir → separate OMEMO device ID) immediately if
 * connect_now, otherwise when the parent sends CONNECT. */
static int run_child(const char *lurch_path, const char *carbons_path,
                     int read_fd, int write_fd, gboolean connect_now) {
    C.read_fd = read_fd;
    C.write_fd = write_fd;

    int flags = fcntl(read_fd, F_GETFL, 0);
    fcntl(read_fd, F_SETFL, flags | O_NONBLOCK);

    system("rm -rf " TEST_USER_DIR_DEV2);
    g_mkdir_with_parents(TEST_USER_DIR_DEV2, 0700);

    if (purple_minimal_init(TEST_USER_DIR_DEV2, &child_conv_uiops) != 0) {
        write(write_fd, "FAIL: init\n", 11);
        return 1;
    }

    if (!load_plugin(lurch_path)) {
        write(write_fd, "FAIL: lurch\n", 12);
        return 1;
    }
    if (carbons_path) {
        load_plugin(carbons_path);
    }

    purple_signal_connect(purple_accounts_get_handle(), "account-signed-on",
                          &C, PURPLE_CALLBACK(child_signed_on), NULL);

    void *jabber_handle = purple_plugins_find_with_id(JABBER_PROTOCOL_ID);
    if (jabber_handle) {
        purple_signal_connect(jabber_handle, "jabber-receiving-xmlnode",
                              &C, PURPLE_CALLBACK(child_xml_recv_cb), NULL);
    }

    C.loop = g_main_loop_new(NULL, FALSE);

    if (connect_now) {
        child_connect();
    }

    g_timeout_add(500, child_check_parent, NULL);
    /* Lifetime deadline past the parent's suite timeout, so the parent
     * never writes into a pipe whose reader is already gone. */
    g_timeout_add_seconds(CHILD_TIMEOUT_S, quit_loop, C.loop);

    fprintf(stderr, "[dev2] entering main loop...\n");
    g_main_loop_run(C.loop);

    g_main_loop_unref(C.loop);
    purple_core_quit();
    g_list_free_full(C.last_dl_ids, g_free);

    system("rm -rf " TEST_USER_DIR_DEV2);
    return 0;
}

/* ================================================================
 * main
 * ================================================================ */

/* Reaps the second-device child without risking an indefinite block:
 * polls waitpid(WNOHANG) for up to timeout_ms, then escalates to
 * SIGKILL, after which the blocking waitpid returns promptly. Safe to
 * call when no child is running. */
void reap_child(int timeout_ms) {
    if (S.child.pid <= 0) {
        return;
    }

    int waited_ms = 0;
    while (waited_ms < timeout_ms) {
        if (waitpid(S.child.pid, NULL, WNOHANG) != 0) {
            S.child.pid = 0;
            return;
        }
        usleep(100 * 1000);
        waited_ms += 100;
    }

    fprintf(stderr, "[harness] child did not exit within %d ms, killing it\n",
            timeout_ms);
    kill(S.child.pid, SIGKILL);
    waitpid(S.child.pid, NULL, 0);
    S.child.pid = 0;
}

/* Parses a "READY <id>" line from the child into S.child.device_id.
 * Returns FALSE if the buffer holds no READY line. */
static gboolean parse_ready(const char *buf) {
    const char *ready = buf ? strstr(buf, "READY") : NULL;
    if (!ready) {
        return FALSE;
    }
    if (sscanf(ready, "READY %u", &S.child.device_id) != 1) {
        S.child.device_id = 0;
    }
    fprintf(stderr, "[harness] second device is online and published (device ID %u)\n",
            S.child.device_id);
    return TRUE;
}

/* Forks bob's second device. Must run before any libpurple init in the
 * parent, so the child gets a clean process. For DEV2_AT_START it then
 * waits (bounded) for the child's READY line, which carries its own
 * device ID; DEV2_ON_DEMAND returns at once and the child waits for
 * second_device_connect. Returns -1 only if the fork itself fails; a
 * child that never reports READY just leaves S.child.device_id at 0
 * and the downstream multi-device assertions fail. */
static int start_second_device(const char *lurch_path, const char *carbons_path,
                               Dev2Mode mode) {
    int p2c[2], c2p[2];
    if (pipe(p2c) < 0 || pipe(c2p) < 0) {
        perror("pipe");
        return -1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return -1;
    }

    if (child == 0) {
        close(p2c[1]);
        close(c2p[0]);
        int ret = run_child(lurch_path, carbons_path, p2c[0], c2p[1],
                            mode == DEV2_AT_START);
        close(p2c[0]);
        close(c2p[1]);
        _exit(ret);
    }

    close(p2c[0]);
    close(c2p[1]);
    S.child.pid = child;
    S.child.read_fd = c2p[0];
    S.child.write_fd = p2c[1];

    if (mode == DEV2_ON_DEMAND) {
        fprintf(stderr, "[harness] second device forked, waiting for CONNECT\n");
        return 0;
    }

    /* Bounded wait for the child's READY: an unbounded read() here
     * would hang the suite before the watchdog even exists if the
     * child wedges without ever writing. */
    fprintf(stderr, "[harness] waiting for second device's devicelist PEP to settle...\n");
    char ready_buf[64] = {0};
    ssize_t rn = 0;
    struct pollfd ready_pfd = { .fd = S.child.read_fd, .events = POLLIN };
    if (poll(&ready_pfd, 1, READY_TIMEOUT_MS) > 0) {
        rn = read(S.child.read_fd, ready_buf, sizeof(ready_buf) - 1);
    }
    if (!parse_ready(rn > 0 ? ready_buf : NULL)) {
        fprintf(stderr, "[harness] WARNING: second device did not signal ready\n");
    }
    return 0;
}

/* In-flight second_device_connect: the callback plus the GLib sources
 * racing to deliver its result (whichever fires first removes the other). */
static void (*dev2_on_ready)(gboolean ok);
static guint dev2_watch_id;
static guint dev2_timeout_id;

/* Delivers the connect result exactly once. */
static void dev2_connect_done(gboolean ok) {
    void (*cb)(gboolean) = dev2_on_ready;
    dev2_on_ready = NULL;
    if (cb) {
        cb(ok);
    }
}

/* fd watch on the child pipe while waiting for READY after CONNECT. */
static gboolean dev2_ready_cb(GIOChannel *src, GIOCondition cond, gpointer data) {
    (void) src;
    (void) cond;
    (void) data;

    dev2_watch_id = 0;
    if (dev2_timeout_id) {
        g_source_remove(dev2_timeout_id);
        dev2_timeout_id = 0;
    }

    char buf[64] = {0};
    ssize_t n = read(S.child.read_fd, buf, sizeof(buf) - 1);
    dev2_connect_done(parse_ready(n > 0 ? buf : NULL));
    return FALSE;
}

/* Gives up on the child's READY after READY_TIMEOUT_MS. */
static gboolean dev2_ready_timeout_cb(gpointer data) {
    (void) data;

    dev2_timeout_id = 0;
    if (dev2_watch_id) {
        g_source_remove(dev2_watch_id);
        dev2_watch_id = 0;
    }
    fprintf(stderr, "[harness] second device did not signal ready after CONNECT\n");
    dev2_connect_done(FALSE);
    return FALSE;
}

/* Tells an ON_DEMAND second device to sign in and waits for its READY
 * without blocking the main loop (XMPP traffic and the watchdog keep
 * running while the child connects). */
void second_device_connect(void (*on_ready)(gboolean ok)) {
    if (S.child.pid <= 0) {
        on_ready(FALSE);
        return;
    }

    dev2_on_ready = on_ready;
    GIOChannel *ch = g_io_channel_unix_new(S.child.read_fd);
    dev2_watch_id = g_io_add_watch(ch, G_IO_IN | G_IO_HUP | G_IO_ERR,
                                   dev2_ready_cb, NULL);
    g_io_channel_unref(ch);
    dev2_timeout_id = g_timeout_add(READY_TIMEOUT_MS, dev2_ready_timeout_cb, NULL);

    fprintf(stderr, "[harness] telling second device to connect...\n");
    write(S.child.write_fd, "CONNECT\n", 8);
}

/* Prints usage to stderr. */
static void usage(const char *prog) {
    fprintf(stderr,
            "usage: %s [--scenario NAME] path/to/lurch.so [path/to/carbons.so]\n"
            "       %s --list\n\nscenarios:\n", prog, prog);
    scenario_list(stderr);
}

/* Suite entry point. Picks the scenario, forks the second-device child
 * if the scenario needs one, then brings up the parent's libpurple,
 * loads plugins, wires signals, and runs the main loop. The child's
 * lifecycle is tied to ours: we send QUIT and reap it on shutdown. */
int main(int argc, char *argv[]) {
    const char *lurch_path = "build/lurch.so";
    const char *carbons_path = NULL;
    const char *scenario_name = "smoke";
    int n_positional = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--list") == 0) {
            scenario_list(stdout);
            return 0;
        } else if (strcmp(argv[i], "--scenario") == 0 && i + 1 < argc) {
            scenario_name = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || argv[i][0] == '-') {
            usage(argv[0]);
            return 2;
        } else if (n_positional == 0) {
            lurch_path = argv[i];
            n_positional++;
        } else if (n_positional == 1) {
            carbons_path = argv[i];
            n_positional++;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    S.scenario = scenario_find(scenario_name);
    if (!S.scenario) {
        fprintf(stderr, "unknown scenario '%s'\n\n", scenario_name);
        usage(argv[0]);
        return 2;
    }

    fprintf(stderr, "\n========================================\n");
    fprintf(stderr, "lurch integration test: %s\n", S.scenario->name);
    fprintf(stderr, "  %s\n", S.scenario->description);
    fprintf(stderr, "========================================\n\n");

    /* A pipe write to an already-dead peer must not kill the process
     * mid-suite — inherited by the child since it's set before fork. */
    signal(SIGPIPE, SIG_IGN);

    if (S.scenario->dev2 != DEV2_NONE) {
        if (start_second_device(lurch_path, carbons_path, S.scenario->dev2) != 0) {
            return 1;
        }
    }

    system("rm -rf " TEST_USER_DIR);
    g_mkdir_with_parents(TEST_USER_DIR, 0700);

    if (purple_minimal_init(TEST_USER_DIR, &conv_uiops) != 0) {
        return 1;
    }

    S.lurch_plugin = load_plugin(lurch_path);
    if (!S.lurch_plugin) {
        test_fail("plugin load", "could not load lurch.so");
        fprintf(stderr, "Results: 0 passed, 1 failed\n");
        return 1;
    }
    test_pass("lurch plugin loaded");

    if (carbons_path) {
        S.carbons_plugin = load_plugin(carbons_path);
        if (!S.carbons_plugin) {
            fprintf(stderr, "[harness] WARNING: carbons plugin not loaded, "
                            "continuing without it\n");
        } else {
            test_pass("carbons plugin loaded");
        }
    }

    purple_signal_connect(purple_accounts_get_handle(), "account-signed-on",
                          &S, PURPLE_CALLBACK(account_signed_on), NULL);
    purple_signal_connect(purple_accounts_get_handle(), "account-signed-off",
                          &S, PURPLE_CALLBACK(account_signed_off), NULL);

    connect_xml_signals();

    S.bob = create_account(BOB_JID, BOB_PASS);

    S.loop = g_main_loop_new(NULL, FALSE);
    g_timeout_add_seconds(TEST_TIMEOUT_S, test_timeout, NULL);

    fprintf(stderr, "[harness] entering main loop (timeout: %ds)...\n\n",
            TEST_TIMEOUT_S);

    g_main_loop_run(S.loop);

    if (S.alice) {
        purple_account_set_enabled(S.alice, "lurch-integration-test", FALSE);
    }
    if (S.bob) {
        purple_account_set_enabled(S.bob, "lurch-integration-test", FALSE);
    }

    if (S.child.pid > 0) {
        write(S.child.write_fd, "QUIT\n", 5);
        reap_child(3000);
    }
    if (S.scenario->dev2 != DEV2_NONE) {
        close(S.child.read_fd);
        close(S.child.write_fd);
    }

    g_main_loop_unref(S.loop);
    purple_core_quit();

    g_list_free_full(S.alice_bob_dl_ids, g_free);
    return S.tests_failed > 0 ? 1 : 0;
}
