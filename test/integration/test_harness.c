/*
 * Integration test harness for lurch OMEMO plugin.
 *
 * Runs a headless libpurple instance with two XMPP accounts (alice, bob)
 * connected to a local Prosody server, loads the lurch plugin, and verifies:
 *
 *   1. Plugin loads successfully
 *   2. Both accounts connect and OMEMO initializes (device lists published)
 *   3. Outgoing message XML contains OMEMO encryption
 *   4. Recipient decrypts the message correctly
 *
 * Usage: ./test_harness [path/to/lurch.so]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <purple.h>

#define TEST_USER_DIR      "/tmp/lurch_integration_test"
#define ALICE_JID          "alice"
#define ALICE_PASS         "testpass_alice"
#define BOB_JID            "bob"
#define BOB_PASS           "testpass_bob"
#define XMPP_SERVER        "localhost"
#define XMPP_PORT_DEFAULT  5222
#define TEST_MESSAGE       "Hello Bob, this is a secret OMEMO message!"
#define OMEMO_NS           "eu.siacs.conversations.axolotl"
#define JABBER_PROTOCOL_ID "prpl-jabber"

/* Test timeout in seconds — abort if tests haven't completed */
#define TEST_TIMEOUT_S     60

/* Delay before sending test message (ms) — allow OMEMO handshake.
 * Rosters are pre-configured in Prosody, so we only need to wait for
 * device list exchange + bundle fetching. */
#define SEND_DELAY_MS      8000

/* ================================================================
 * Test state
 * ================================================================ */
typedef struct {
    GMainLoop    *loop;
    PurplePlugin *lurch_plugin;

    PurpleAccount *alice;
    PurpleAccount *bob;

    gboolean alice_connected;
    gboolean bob_connected;

    /* results */
    gboolean omemo_xml_seen;       /* outgoing XML had OMEMO encrypted element */
    gboolean plaintext_leaked;     /* outgoing XML contained plaintext body */
    gboolean message_received;     /* bob's conv got a message */
    gboolean message_correct;      /* bob got the right plaintext */

    int tests_passed;
    int tests_failed;
} TestState;

static TestState S = {0};

/* ================================================================
 * Helpers
 * ================================================================ */

static void test_pass(const char *name) {
    fprintf(stderr, "  PASS  %s\n", name);
    S.tests_passed++;
}

static void test_fail(const char *name, const char *reason) {
    fprintf(stderr, "  FAIL  %s — %s\n", name, reason);
    S.tests_failed++;
}

static void finish_tests(void) {
    fprintf(stderr, "\n========================================\n");

    /* Test 1: plugin loaded (already checked at startup) */

    /* Test 2: both accounts connected */
    if (S.alice_connected && S.bob_connected)
        test_pass("both accounts connected");
    else
        test_fail("both accounts connected",
                  !S.alice_connected ? "alice failed" : "bob failed");

    /* Test 3: outgoing XML was OMEMO-encrypted */
    if (S.omemo_xml_seen)
        test_pass("outgoing XML contains OMEMO encryption");
    else
        test_fail("outgoing XML contains OMEMO encryption",
                  "no <encrypted> element seen");

    /* Test 4: plaintext body not leaked */
    if (!S.plaintext_leaked)
        test_pass("plaintext body not leaked in XML");
    else
        test_fail("plaintext body not leaked in XML",
                  "<body> with test message found in wire XML");

    /* Test 5: bob received and decrypted message */
    if (S.message_correct)
        test_pass("bob received decrypted message");
    else if (S.message_received)
        test_fail("bob received decrypted message", "message received but content wrong");
    else
        test_fail("bob received decrypted message", "no message received");

    fprintf(stderr, "========================================\n");
    fprintf(stderr, "Results: %d passed, %d failed\n\n",
            S.tests_passed, S.tests_failed);

    g_main_loop_quit(S.loop);
}

/* ================================================================
 * GLib-backed libpurple event loop
 * ================================================================ */

typedef struct {
    PurpleInputFunction func;
    gpointer            data;
} GLibIOClosure;

static gboolean glib_io_invoke(GIOChannel *src, GIOCondition cond, gpointer data) {
    GLibIOClosure *closure = data;
    PurpleInputCondition pc = 0;

    if (cond & (G_IO_IN  | G_IO_HUP | G_IO_ERR))
        pc |= PURPLE_INPUT_READ;
    if (cond & (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL))
        pc |= PURPLE_INPUT_WRITE;

    closure->func(closure->data, g_io_channel_unix_get_fd(src), pc);
    return TRUE;
}

static guint glib_input_add(gint fd, PurpleInputCondition cond,
                            PurpleInputFunction func, gpointer data) {
    GLibIOClosure *closure = g_new0(GLibIOClosure, 1);
    GIOCondition gc = 0;

    closure->func = func;
    closure->data = data;

    if (cond & PURPLE_INPUT_READ)
        gc |= G_IO_IN | G_IO_HUP | G_IO_ERR;
    if (cond & PURPLE_INPUT_WRITE)
        gc |= G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL;

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
 * Conversation UI ops — captures messages for bob
 * ================================================================ */

static void conv_create(PurpleConversation *conv) {
    fprintf(stderr, "[harness] conversation created: %s (account: %s)\n",
            purple_conversation_get_name(conv),
            purple_account_get_username(purple_conversation_get_account(conv)));
}

static void conv_write_im(PurpleConversation *conv, const char *who,
                           const char *message, PurpleMessageFlags flags,
                           time_t mtime) {
    PurpleAccount *acc = purple_conversation_get_account(conv);

    fprintf(stderr, "[harness] write_im: account=%s who=%s flags=0x%x msg='%.80s'\n",
            purple_account_get_username(acc),
            who ? who : "(null)", flags,
            message ? message : "(null)");

    /* We care about messages received by bob (not sent by bob) */
    if (acc == S.bob && !(flags & PURPLE_MESSAGE_SEND) && message) {
        S.message_received = TRUE;
        if (strstr(message, TEST_MESSAGE)) {
            S.message_correct = TRUE;
            fprintf(stderr, "[harness] *** bob received correct decrypted message ***\n");
        }
    }
}

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
 * XML capture — hooks into jabber-sending-xmlnode
 *
 * This runs AFTER lurch has processed the stanza (lurch uses a very
 * high priority), so we see the encrypted result.
 * ================================================================ */

static void xml_recv_cb(PurpleConnection *gc, xmlnode **stanza_pp) {
    if (!stanza_pp || !*stanza_pp)
        return;

    xmlnode *stanza = *stanza_pp;
    const char *name = stanza->name;
    if (!name)
        return;

    /* Only log PEP events (message type=headline with <event>) and IQ exchanges */
    if (strcmp(name, "message") == 0) {
        const char *type = xmlnode_get_attrib(stanza, "type");
        if (type && strcmp(type, "headline") == 0) {
            PurpleAccount *acc = purple_connection_get_account(gc);
            char *xml_str = xmlnode_to_str(stanza, NULL);
            if (xml_str) {
                fprintf(stderr, "[harness] incoming PEP event for %s:\n%s\n",
                        purple_account_get_username(acc), xml_str);
                g_free(xml_str);
            }
        }
    } else if (strcmp(name, "iq") == 0) {
        PurpleAccount *acc = purple_connection_get_account(gc);
        char *xml_str = xmlnode_to_str(stanza, NULL);
        if (xml_str) {
            fprintf(stderr, "[harness] incoming IQ for %s:\n%s\n",
                    purple_account_get_username(acc), xml_str);
            g_free(xml_str);
        }
    }
}

static void xml_sent_cb(PurpleConnection *gc, xmlnode **stanza_pp) {
    if (!stanza_pp || !*stanza_pp)
        return;

    xmlnode *stanza = *stanza_pp;
    const char *name = stanza->name;
    if (!name)
        return;

    PurpleAccount *acc = purple_connection_get_account(gc);

    /* Log all outgoing IQ stanzas for PEP debugging */
    if (strcmp(name, "iq") == 0) {
        char *xml_str = xmlnode_to_str(stanza, NULL);
        if (xml_str) {
            fprintf(stderr, "[harness] outgoing IQ from %s:\n%s\n",
                    purple_account_get_username(acc), xml_str);
            g_free(xml_str);
        }
        return;
    }

    if (strcmp(name, "message") != 0)
        return;

    const char *to = xmlnode_get_attrib(stanza, "to");
    if (!to)
        return;

    char *xml_str = xmlnode_to_str(stanza, NULL);
    if (xml_str) {
        fprintf(stderr, "[harness] outgoing message from %s:\n%s\n",
                purple_account_get_username(acc), xml_str);
    }

    /* Check for OMEMO encrypted element */
    xmlnode *encrypted = xmlnode_get_child_with_namespace(stanza, "encrypted", OMEMO_NS);
    if (encrypted) {
        S.omemo_xml_seen = TRUE;
        fprintf(stderr, "[harness] *** OMEMO <encrypted> element found ***\n");
    }

    /* Check for plaintext leak */
    xmlnode *body = xmlnode_get_child(stanza, "body");
    if (body) {
        char *body_text = xmlnode_get_data(body);
        if (body_text && strstr(body_text, TEST_MESSAGE)) {
            S.plaintext_leaked = TRUE;
            fprintf(stderr, "[harness] *** WARNING: plaintext body leaked ***\n");
        }
        g_free(body_text);
    }

    g_free(xml_str);
}

/* ================================================================
 * Account status callbacks
 * ================================================================ */

static gboolean send_test_message(gpointer data);
static PurpleAccount *create_account(const char *user, const char *pass);

/* Connect alice after bob is online and caps are exchanged, so that
 * PEP device list notifications flow correctly between them. */
static gboolean connect_alice(gpointer data) {
    (void) data;
    fprintf(stderr, "[harness] connecting alice...\n");
    S.alice = create_account(ALICE_JID, ALICE_PASS);
    return FALSE;
}

static void account_signed_on(PurpleAccount *account) {
    const char *user = purple_account_get_username(account);
    fprintf(stderr, "[harness] account signed on: %s\n", user);

    if (account == S.bob && !S.bob_connected) {
        S.bob_connected = TRUE;
        /* Give bob time to publish device list and exchange caps,
         * then connect alice so she receives bob's PEP notification. */
        g_timeout_add(3000, connect_alice, NULL);
    } else if (account == S.alice) {
        S.alice_connected = TRUE;
        fprintf(stderr, "[harness] both accounts online, sending test message in %d ms...\n",
                SEND_DELAY_MS);
        g_timeout_add(SEND_DELAY_MS, send_test_message, NULL);
    }
}

static void account_signed_off(PurpleAccount *account) {
    fprintf(stderr, "[harness] account signed off: %s\n",
            purple_account_get_username(account));
}

/* ================================================================
 * Test message sending
 * ================================================================ */

static gboolean send_test_message(gpointer data) {
    (void) data;

    fprintf(stderr, "[harness] sending test message from alice to bob@localhost...\n");

    PurpleConversation *conv = purple_conversation_new(
        PURPLE_CONV_TYPE_IM, S.alice, "bob@localhost");

    if (!conv) {
        fprintf(stderr, "[harness] ERROR: failed to create conversation\n");
        finish_tests();
        return FALSE;
    }

    purple_conv_im_send(PURPLE_CONV_IM(conv), TEST_MESSAGE);

    fprintf(stderr, "[harness] message sent, waiting for delivery...\n");

    /* Give some time for delivery + decryption, then collect results */
    g_timeout_add(5000, (GSourceFunc) finish_tests, NULL);

    return FALSE;  /* one-shot timer */
}

/* ================================================================
 * Test timeout
 * ================================================================ */

static gboolean test_timeout(gpointer data) {
    (void) data;
    fprintf(stderr, "\n[harness] TEST TIMEOUT after %d seconds\n", TEST_TIMEOUT_S);
    finish_tests();
    return FALSE;
}

/* ================================================================
 * libpurple initialization
 * ================================================================ */

static int init_libpurple(void) {
    /* Set a custom user directory so we don't pollute ~/.purple */
    purple_util_set_user_dir(TEST_USER_DIR);

    purple_eventloop_set_ui_ops(&eventloop_uiops);
    purple_conversations_set_ui_ops(&conv_uiops);

    /* Disable debug output unless PURPLE_DEBUG is set */
    purple_debug_set_enabled(getenv("PURPLE_DEBUG") != NULL);

    if (!purple_core_init("lurch-integration-test")) {
        fprintf(stderr, "[harness] ERROR: purple_core_init failed\n");
        return -1;
    }

    purple_set_blist(purple_blist_new());
    purple_blist_load();
    purple_prefs_load();

    return 0;
}

static PurplePlugin *load_lurch(const char *plugin_path) {
    PurplePlugin *plugin = purple_plugin_probe(plugin_path);
    if (!plugin) {
        fprintf(stderr, "[harness] ERROR: purple_plugin_probe failed for %s\n",
                plugin_path);
        return NULL;
    }

    if (!purple_plugin_load(plugin)) {
        fprintf(stderr, "[harness] ERROR: purple_plugin_load failed for %s\n",
                plugin_path);
        return NULL;
    }

    fprintf(stderr, "[harness] lurch plugin loaded: %s\n",
            purple_plugin_get_name(plugin));
    return plugin;
}

static PurpleAccount *create_account(const char *user, const char *pass) {
    char jid[256];
    snprintf(jid, sizeof(jid), "%s@%s", user, XMPP_SERVER);

    PurpleAccount *acc = purple_account_new(jid, JABBER_PROTOCOL_ID);
    purple_account_set_password(acc, pass);

    /* Disable TLS requirement for local test server */
    purple_account_set_bool(acc, "require_tls", FALSE);
    const char *port_str = getenv("XMPP_PORT");
    int port = (port_str && atoi(port_str)) ? atoi(port_str) : XMPP_PORT_DEFAULT;
    purple_account_set_int(acc, "port", port);

    /* Enable the account (triggers connection) */
    purple_account_set_enabled(acc, "lurch-integration-test", TRUE);

    fprintf(stderr, "[harness] account created and enabled: %s\n", jid);
    return acc;
}

static void connect_xml_signal(void) {
    void *jabber_handle = purple_plugins_find_with_id(JABBER_PROTOCOL_ID);
    if (!jabber_handle) {
        fprintf(stderr, "[harness] WARNING: jabber plugin not found, "
                        "cannot capture XML\n");
        return;
    }

    /* Connect at highest priority so we see the stanza AFTER lurch
     * has processed it (lurch uses HIGHEST-100). In libpurple, higher
     * priority handlers fire last, getting the final version. */
    purple_signal_connect_priority(jabber_handle, "jabber-sending-xmlnode",
                          &S, PURPLE_CALLBACK(xml_sent_cb), NULL,
                          PURPLE_SIGNAL_PRIORITY_HIGHEST);
    purple_signal_connect(jabber_handle, "jabber-receiving-xmlnode",
                          &S, PURPLE_CALLBACK(xml_recv_cb), NULL);

    fprintf(stderr, "[harness] XML capture signals connected\n");
}

/* ================================================================
 * main
 * ================================================================ */

int main(int argc, char *argv[]) {
    const char *plugin_path = "build/lurch.so";
    if (argc > 1)
        plugin_path = argv[1];

    fprintf(stderr, "\n========================================\n");
    fprintf(stderr, "lurch integration test harness\n");
    fprintf(stderr, "========================================\n\n");

    /* Clean previous test state */
    system("rm -rf " TEST_USER_DIR);
    g_mkdir_with_parents(TEST_USER_DIR, 0700);

    /* Init libpurple */
    if (init_libpurple() != 0)
        return 1;

    /* Load lurch plugin */
    S.lurch_plugin = load_lurch(plugin_path);
    if (!S.lurch_plugin) {
        test_fail("plugin load", "could not load lurch.so");
        fprintf(stderr, "Results: 0 passed, 1 failed\n");
        return 1;
    }
    test_pass("plugin loaded");

    /* Connect signals */
    purple_signal_connect(purple_accounts_get_handle(), "account-signed-on",
                          &S, PURPLE_CALLBACK(account_signed_on), NULL);
    purple_signal_connect(purple_accounts_get_handle(), "account-signed-off",
                          &S, PURPLE_CALLBACK(account_signed_off), NULL);

    connect_xml_signal();

    /* Connect bob first; alice will be connected after bob's OMEMO init
     * completes (triggered from account_signed_on callback). */
    S.bob = create_account(BOB_JID, BOB_PASS);

    /* Set up the main loop with a timeout */
    S.loop = g_main_loop_new(NULL, FALSE);
    g_timeout_add_seconds(TEST_TIMEOUT_S, test_timeout, NULL);

    fprintf(stderr, "[harness] entering main loop (timeout: %ds)...\n\n",
            TEST_TIMEOUT_S);

    g_main_loop_run(S.loop);

    /* Cleanup */
    purple_account_set_enabled(S.alice, "lurch-integration-test", FALSE);
    purple_account_set_enabled(S.bob,   "lurch-integration-test", FALSE);

    g_main_loop_unref(S.loop);
    purple_core_quit();

    return S.tests_failed > 0 ? 1 : 0;
}
