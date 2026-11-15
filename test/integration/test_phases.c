/*
 * Test phases and scenarios for the lurch integration test harness.
 *
 * A scenario is a named list of phases (see the registry at the bottom
 * of this file). The "smoke" scenario covers normal operation:
 *   - Basic encryption/decryption (alice->bob)
 *   - Bidirectional messaging (bob->alice reply)
 *   - Rapid burst of messages (session state stability)
 *   - Multi-device delivery via carbons + key verification
 *   - API disable/enable + behavior verification
 *   - Multibyte UTF-8 message body round-trip
 *   - Offline messaging
 *   - Reconnect (+ device ID stability)
 *   - Non-OMEMO peer
 * Along the way it asserts that the server-side devicelists match the
 * devices that actually exist.
 *
 * The "devicelist-update" scenario brings bob's second device online
 * while alice is already connected, and checks that the resulting
 * devicelist update reaches alice live and that lurch acts on it.
 */

#include "test_harness.h"

/* ================================================================
 * Phase-local state (set + read only inside this file)
 * ================================================================ */

/* Latch for the lurch-status / enable / disable callbacks. They share
 * one set of fields because they're always polled by a single chained
 * step; nothing observes them concurrently. */
static gboolean api_called;
static int      api_err;
static int      api_status;

/* bob's two device IDs (primary, second device) as asserted against
 * the server in the multi-device phase; the reconnect phase asserts
 * the server still lists exactly these. */
static uint32_t bob_server_ids[2];

/* Snapshot of bob's device IDs taken via lurch-fp-other BEFORE bob
 * disconnects, copied because the GHashTable lurch returns is freed
 * after the callback. Compared against a fresh query after reconnect. */
static GList *bob_ids_saved;

/* ================================================================
 * Lurch API signal callbacks
 *
 * These all fire synchronously from inside purple_signal_emit, so each
 * test step can call emit() and trust the result is already latched
 * (or, where the callback does the assertion directly, already reported).
 * ================================================================ */

/* Latches the result of a lurch-status-im query for the next step to
 * read; status callers care about both the error and the status enum. */
static void api_status_im_cb(int32_t err, int status, void *user_data) {
    fprintf(stderr, "[harness] api_status_im_cb: err=%d status=%d\n", err, status);
    api_called = TRUE;
    api_err = err;
    api_status = status;
}

/* Latches the result of lurch-enable-im / lurch-disable-im. Only the
 * error is meaningful — the operation either succeeded or didn't. */
static void api_enable_disable_cb(int32_t err, void *user_data) {
    fprintf(stderr, "[harness] api_enable_disable_cb: err=%d\n", err);
    api_called = TRUE;
    api_err = err;
}

/* Asserts that lurch knows bob has exactly two devices (the parent and
 * the forked-child second device). Per-device key coverage is checked
 * behaviorally by carbon-decrypting at both devices, not by parsing
 * the outgoing stanza. */
static void multi_device_bob_check_cb(int32_t err, GHashTable *id_fp_table,
                                       void *user_data) {
    fprintf(stderr, "[harness] multi_device_bob_check_cb: err=%d size=%u\n",
            err, id_fp_table ? g_hash_table_size(id_fp_table) : 0);

    if (err != 0 || !id_fp_table) {
        test_fail("multi-device: bob devicelist", "lurch-fp-other failed");
        return;
    }

    guint n = g_hash_table_size(id_fp_table);
    if (n == 2) {
        test_pass("multi-device: bob has 2 devices in devicelist");
    } else {
        char reason[64];
        snprintf(reason, sizeof(reason), "expected 2, got %u", n);
        test_fail("multi-device: bob device count", reason);
    }
}

/* Copies bob's current device IDs into bob_ids_saved. Used to take a
 * pre-disconnect snapshot; the table is destroyed after this returns,
 * but we need to compare across an async gap (reconnect), so we own
 * a copy. */
static void snapshot_bob_devices_cb(int32_t err, GHashTable *id_fp_table,
                                     void *user_data) {
    fprintf(stderr, "[harness] snapshot_bob_devices_cb: err=%d size=%u\n",
            err, id_fp_table ? g_hash_table_size(id_fp_table) : 0);
    g_list_free_full(bob_ids_saved, g_free);
    bob_ids_saved = NULL;
    if (err != 0 || !id_fp_table) {
        return;
    }
    GHashTableIter it;
    gpointer key, val;
    g_hash_table_iter_init(&it, id_fp_table);
    while (g_hash_table_iter_next(&it, &key, &val)) {
        uint32_t *id = g_new(uint32_t, 1);
        *id = *(uint32_t *)key;
        bob_ids_saved = g_list_append(bob_ids_saved, id);
    }
}

/* Reconnect stability check: verifies every device ID we saw before
 * bob disconnected is still present in lurch's view after he comes
 * back. A regenerated ID would break OMEMO sessions for every peer. */
static void check_bob_stability_cb(int32_t err, GHashTable *id_fp_table,
                                    void *user_data) {
    fprintf(stderr, "[harness] check_bob_stability_cb: err=%d size=%u\n",
            err, id_fp_table ? g_hash_table_size(id_fp_table) : 0);

    if (!bob_ids_saved) {
        test_fail("reconnect: device ID stability", "no pre-disconnect snapshot");
        return;
    }
    if (err != 0 || !id_fp_table) {
        test_fail("reconnect: device ID stability", "post-reconnect query failed");
        return;
    }

    for (GList *l = bob_ids_saved; l; l = l->next) {
        uint32_t saved = *(uint32_t *)l->data;
        if (!g_hash_table_contains(id_fp_table, &saved)) {
            char reason[64];
            snprintf(reason, sizeof(reason),
                     "device %u disappeared after reconnect", saved);
            test_fail("reconnect: device ID stability", reason);
            g_list_free_full(bob_ids_saved, g_free);
            bob_ids_saved = NULL;
            return;
        }
    }
    test_pass("reconnect: device IDs stable across disconnect");
    g_list_free_full(bob_ids_saved, g_free);
    bob_ids_saved = NULL;
}

/* ================================================================
 * Phase: alice -> bob
 * ================================================================ */

static gboolean check_alice_bob(gpointer data);

/* First message of the scenario: alice sends to bob. */
static gboolean alice_bob_start(gpointer data) {
    (void) data;
    fprintf(stderr, "\n--- phase: alice -> bob ---\n");
    fprintf(stderr, "[harness] sending message from alice to bob...\n");
    await_messages(S.bob, MSG_ALICE_BOB, 1, check_alice_bob, 10000);
    send_im(S.alice, "bob@localhost", MSG_ALICE_BOB);
    return FALSE;
}

/* Asserts encryption (plaintext absent from the outgoing wire) and
 * delivery (bob's conv hook saw a matching message), then that the
 * server lists exactly alice's one device. */
static gboolean check_alice_bob(gpointer data) {
    (void) data;

    if (S.sent_text && strstr(S.sent_text, MSG_ALICE_BOB)) {
        test_fail("alice -> bob", "plaintext on the wire (not encrypted)");
    } else if (S.wait.got < 1) {
        test_fail("alice -> bob", "bob did not receive correct message");
    } else {
        test_pass("alice -> bob: encrypted and decrypted");
    }

    uint32_t alice_id = own_device_id(S.alice);
    assert_server_devicelist("server: alice's devicelist lists her one device",
                             ALICE_JID "@" XMPP_SERVER, &alice_id, 1);

    next_phase();
    return FALSE;
}

/* ================================================================
 * Phase: bob -> alice (bidirectional)
 * ================================================================ */

static gboolean check_bob_alice(gpointer data);

/* bob replies to alice. */
static gboolean bob_alice_start(gpointer data) {
    (void) data;
    fprintf(stderr, "\n--- phase: bob -> alice (bidirectional) ---\n");
    fprintf(stderr, "[harness] sending reply from bob to alice...\n");
    await_messages(S.alice, MSG_BOB_ALICE, 1, check_bob_alice, 10000);
    send_im(S.bob, "alice@localhost", MSG_BOB_ALICE);
    return FALSE;
}

/* Verifies the reverse direction works too: bob's reply to alice is
 * encrypted and decrypts correctly. Catches asymmetries where one
 * direction's sessions are healthy but the other is not. */
static gboolean check_bob_alice(gpointer data) {
    (void) data;

    if (S.sent_text && strstr(S.sent_text, MSG_BOB_ALICE)) {
        test_fail("bob -> alice", "plaintext on the wire (not encrypted)");
    } else if (S.wait.got < 1) {
        test_fail("bob -> alice", "alice did not receive correct message");
    } else {
        test_pass("bob -> alice: bidirectional OMEMO works");
    }

    next_phase();
    return FALSE;
}

/* ================================================================
 * Phase: multiple messages
 * ================================================================ */

static gboolean check_multi_msg(gpointer data);

/* Sends MULTI_MSG_COUNT messages back to back. */
static gboolean multi_msg_start(gpointer data) {
    (void) data;
    fprintf(stderr, "\n--- phase: multiple messages ---\n");
    fprintf(stderr, "[harness] sending %d messages from alice to bob...\n",
            MULTI_MSG_COUNT);
    await_messages(S.bob, "Multi message #", MULTI_MSG_COUNT,
                   check_multi_msg, 10000);
    for (int i = 0; i < MULTI_MSG_COUNT; i++) {
        char msg[128];
        snprintf(msg, sizeof(msg), MSG_MULTI_FMT, i + 1);
        send_im(S.alice, "bob@localhost", msg);
    }
    return FALSE;
}

/* Stress-style check: a burst of MULTI_MSG_COUNT messages should all
 * encrypt and deliver. Targets session-state corruption bugs that
 * only surface when the ratchet steps multiple times in succession. */
static gboolean check_multi_msg(gpointer data) {
    (void) data;

    /* sent_text accumulates every outgoing message in the phase, so
     * a plaintext leak in ANY of the N sends shows up here. */
    if (S.sent_text && strstr(S.sent_text, "Multi message #")) {
        test_fail("multiple messages", "plaintext on the wire");
    } else if (S.wait.got < MULTI_MSG_COUNT) {
        char reason[128];
        snprintf(reason, sizeof(reason), "wanted %d, got %d",
                 MULTI_MSG_COUNT, S.wait.got);
        test_fail("multiple messages", reason);
    } else {
        test_pass("multiple messages: all encrypted and received");
    }

    next_phase();
    return FALSE;
}

/* ================================================================
 * Phase: multi-device
 * ================================================================ */

static gboolean multi_device_check(gpointer data);

/* GLib source IDs for the in-flight child-report wait; whichever of
 * the fd watch / fallback timer fires first removes the other. */
static guint child_report_watch_id;
static guint child_report_timeout_id;

/* Entry point for the multi-device phase: tells the forked child to
 * start listening, then sends the test message. Both devices
 * decrypting via carbons is what proves the wire-level fan-out worked
 * (no need to inspect header sid / key rids ourselves). */
static gboolean multi_device_start(gpointer data) {
    (void) data;
    fprintf(stderr, "\n--- phase: multi-device (bob's second device) ---\n");

    if (S.child.pid <= 0) {
        test_fail("multi-device", "child process not running");
        next_phase();
        return FALSE;
    }

    /* Tell the child to start listening */
    write(S.child.write_fd, "SEND\n", 5);

    fprintf(stderr, "[harness] sending message for multi-device test...\n");
    await_messages(S.bob, MSG_MULTI_DEV, 1, multi_device_check, 12000);
    send_im(S.alice, "bob@localhost", MSG_MULTI_DEV);
    return FALSE;
}

/* Wraps up the multi-device phase once the child's verdict is in (or
 * the wait for it gave up): reports the second-device result, checks
 * alice's view of bob's devices (lurch-fp-other) and the server's
 * (the stored devicelist), and shuts the child down. */
static void multi_device_finish(const char *child_result) {
    if (child_result && strstr(child_result, "PASS")) {
        test_pass("multi-device: second device received message via carbons");
    } else if (child_result) {
        test_fail("multi-device: second device", child_result);
    } else {
        test_fail("multi-device: second device", "no response from child");
    }

    /* Ask lurch for bob's devicelist; the callback fires synchronously
     * and asserts the device count against the table. */
    purple_signal_emit(purple_plugins_get_handle(), "lurch-fp-other",
                       S.alice, "bob@localhost",
                       multi_device_bob_check_cb, NULL);

    /* alice's cache can look right while the server is wrong (that is
     * the shape of the devicelist bug), so check the server too. */
    bob_server_ids[0] = own_device_id(S.bob);
    bob_server_ids[1] = S.child.device_id;
    assert_server_devicelist("server: bob's devicelist lists both devices",
                             BOB_JID "@" XMPP_SERVER, bob_server_ids, 2);

    write(S.child.write_fd, "QUIT\n", 5);
    reap_child(2000);

    next_phase();
}

/* fd watch on the child pipe: fires when the child's PASS/FAIL report
 * (or EOF) arrives, so the main loop keeps running while we wait —
 * a blocking poll() here would freeze all XMPP I/O and every timer,
 * including the suite watchdog. */
static gboolean multi_device_child_report_cb(GIOChannel *src, GIOCondition cond,
                                             gpointer data) {
    (void) src;
    (void) cond;
    (void) data;

    child_report_watch_id = 0;
    if (child_report_timeout_id) {
        g_source_remove(child_report_timeout_id);
        child_report_timeout_id = 0;
    }

    char buf[64] = {0};
    ssize_t n = read(S.child.read_fd, buf, sizeof(buf) - 1);
    multi_device_finish(n > 0 ? buf : NULL);
    return FALSE;
}

/* Fallback if the child never reports: tears down the fd watch and
 * finishes the phase with a "no response" failure. */
static gboolean multi_device_child_timeout_cb(gpointer data) {
    (void) data;

    child_report_timeout_id = 0;
    if (child_report_watch_id) {
        g_source_remove(child_report_watch_id);
        child_report_watch_id = 0;
    }

    multi_device_finish(NULL);
    return FALSE;
}

/* Runs when the parent's bob has received the message (or the await
 * timed out): records the primary-device result, then arms a
 * non-blocking wait for the second device's verdict. */
static gboolean multi_device_check(gpointer data) {
    (void) data;

    if (S.wait.got >= 1) {
        test_pass("multi-device: primary device received message");
    } else {
        test_fail("multi-device: primary device", "did not receive message");
    }

    GIOChannel *ch = g_io_channel_unix_new(S.child.read_fd);
    child_report_watch_id = g_io_add_watch(ch, G_IO_IN | G_IO_HUP | G_IO_ERR,
                                           multi_device_child_report_cb, NULL);
    g_io_channel_unref(ch);
    child_report_timeout_id = g_timeout_add(10000, multi_device_child_timeout_cb,
                                            NULL);
    return FALSE;
}

/* ================================================================
 * Phase: live devicelist update (second device appears while alice
 * is online)
 * ================================================================ */

/* How long to wait for alice to receive bob's updated devicelist
 * after the second device reports READY, and how often to look. */
#define DL_UPDATE_TIMEOUT_MS 10000
#define DL_UPDATE_POLL_MS    200

static int dl_update_waited_ms;

/* Latches the size of alice's cached devicelist for bob. */
static void count_bob_devices_cb(int32_t err, GHashTable *id_fp_table, void *user_data) {
    int *out = user_data;
    *out = (err == 0 && id_fp_table) ? (int) g_hash_table_size(id_fp_table) : -1;
}

/* Asks alice's lurch how many devices it knows for bob (-1 on error). */
static int alice_known_bob_devices(void) {
    int n = -1;
    purple_signal_emit(purple_plugins_get_handle(), "lurch-fp-other",
                       S.alice, "bob@localhost", count_bob_devices_cb, &n);
    return n;
}

/* Asserts that alice's lurch knows exactly `want` devices for bob. */
static void assert_alice_knows_bob_devices(const char *name, int want) {
    int n = alice_known_bob_devices();
    if (n == want) {
        test_pass(name);
    } else {
        char reason[64];
        snprintf(reason, sizeof(reason), "expected %d, got %d", want, n);
        test_fail(name, reason);
    }
}

/* Polls until the latest devicelist event alice got from bob lists the
 * new device, then checks that alice's lurch picked it up too. Polling
 * (rather than reacting inside the stanza hook) gives lurch's own PEP
 * handler, which runs after the hook, time to process the event. */
static gboolean dl_update_poll(gpointer data) {
    (void) data;

    gboolean seen = S.child.device_id && alice_saw_bob_device(S.child.device_id);
    if (!seen && dl_update_waited_ms < DL_UPDATE_TIMEOUT_MS) {
        dl_update_waited_ms += DL_UPDATE_POLL_MS;
        g_timeout_add(DL_UPDATE_POLL_MS, dl_update_poll, NULL);
        return FALSE;
    }

    if (seen) {
        test_pass("devicelist update: alice received live update listing the new device");
    } else {
        char reason[128];
        snprintf(reason, sizeof(reason),
                 "%d devicelist event(s) from bob since connect, none listing device %u",
                 S.alice_bob_dl_events, S.child.device_id);
        test_fail("devicelist update: alice received live update", reason);
    }

    assert_alice_knows_bob_devices("devicelist update: alice's lurch knows both bob devices", 2);

    next_phase();
    return FALSE;
}

/* Called once the second device reported READY (or didn't). */
static void dl_update_dev2_ready(gboolean ok) {
    if (!ok) {
        test_fail("devicelist update: second device", "did not come online");
        next_phase();
        return;
    }
    dl_update_waited_ms = 0;
    g_timeout_add(DL_UPDATE_POLL_MS, dl_update_poll, NULL);
}

/* Entry point: checks alice knows only bob's primary device, then
 * brings the second device online and watches for the update. */
static gboolean dl_update_start(gpointer data) {
    (void) data;
    fprintf(stderr, "\n--- phase: live devicelist update ---\n");

    assert_alice_knows_bob_devices("devicelist update: alice knows 1 bob device before", 1);

    /* Only events after this point count as the update. */
    S.alice_bob_dl_events = 0;
    second_device_connect(dl_update_dev2_ready);
    return FALSE;
}

/* ================================================================
 * Phase: disable OMEMO via API
 * ================================================================ */

static gboolean api_disable_step2(gpointer data);
static gboolean api_disable_step3(gpointer data);
static gboolean api_disable_step4(gpointer data);
static gboolean api_disable_send_check(gpointer data);
static gboolean api_disable_recv_check(gpointer data);

/* First step of the disable-via-API phase: asks lurch what bob's
 * OMEMO status is right now (expected: OK). The callback fires
 * synchronously; step 2 runs from an idle callback only so each step
 * starts at the top level of the main loop. */
static gboolean api_disable_step1(gpointer data) {
    (void) data;
    fprintf(stderr, "\n--- phase: disable OMEMO via API ---\n");
    fprintf(stderr, "[harness] checking OMEMO status for bob...\n");

    api_called = FALSE;
    purple_signal_emit(purple_plugins_get_handle(), "lurch-status-im",
                       S.alice, "bob@localhost",
                       api_status_im_cb, NULL);

    g_idle_add(api_disable_step2, NULL);
    return FALSE;
}

/* Asserts step 1's status was OK, then fires the actual disable. */
static gboolean api_disable_step2(gpointer data) {
    (void) data;

    if (api_called && api_err == 0 && api_status == LURCH_STATUS_OK) {
        test_pass("OMEMO status is OK before disable");
    } else {
        char reason[128];
        snprintf(reason, sizeof(reason), "cb=%d err=%d status=%d (expected OK=%d)",
                 api_called, api_err, api_status, LURCH_STATUS_OK);
        test_fail("OMEMO status before disable", reason);
    }

    fprintf(stderr, "[harness] disabling OMEMO for bob via API...\n");
    api_called = FALSE;
    purple_signal_emit(purple_plugins_get_handle(), "lurch-disable-im",
                       S.alice, "bob@localhost",
                       api_enable_disable_cb, NULL);

    g_idle_add(api_disable_step3, NULL);
    return FALSE;
}

/* Asserts the disable callback was a success, then queries status
 * again to confirm lurch has actually applied the change. */
static gboolean api_disable_step3(gpointer data) {
    (void) data;

    if (api_called && api_err == 0) {
        test_pass("disable OMEMO via API succeeded");
    } else {
        test_fail("disable OMEMO via API", "callback error");
    }

    /* Check status is now DISABLED */
    api_called = FALSE;
    purple_signal_emit(purple_plugins_get_handle(), "lurch-status-im",
                       S.alice, "bob@localhost",
                       api_status_im_cb, NULL);

    g_idle_add(api_disable_step4, NULL);
    return FALSE;
}

/* Asserts status is now DISABLED, then sends a message while disabled
 * to verify lurch actually sends it in the clear (not encrypted). */
static gboolean api_disable_step4(gpointer data) {
    (void) data;

    if (api_called && api_err == 0 && api_status == LURCH_STATUS_DISABLED) {
        test_pass("OMEMO status is DISABLED after disable");
    } else {
        char reason[128];
        snprintf(reason, sizeof(reason), "cb=%d err=%d status=%d (expected DISABLED=%d)",
                 api_called, api_err, api_status, LURCH_STATUS_DISABLED);
        test_fail("OMEMO status after disable", reason);
    }

    /* Send a message while disabled — should NOT be OMEMO-encrypted */
    reset_phase_counters();
    fprintf(stderr, "[harness] sending message while OMEMO disabled...\n");
    await_messages(S.bob, MSG_DISABLED_SEND, 1, api_disable_send_check, 10000);
    send_im(S.alice, "bob@localhost", MSG_DISABLED_SEND);
    return FALSE;
}

/* Confirms the disabled-state send was NOT OMEMO-encrypted, then
 * tests the asymmetric case: bob (whose lurch isn't disabled) sends
 * encrypted to alice, and alice should still decrypt it — receiving
 * is unconditional. */
static gboolean api_disable_send_check(gpointer data) {
    (void) data;

    /* Expecting plaintext on the wire — disable means lurch should
     * NOT encrypt, so MSG_DISABLED_SEND should appear in sent_text. */
    if (S.sent_text && strstr(S.sent_text, MSG_DISABLED_SEND)) {
        test_pass("disabled: sent message not OMEMO-encrypted");
    } else {
        test_fail("disabled: sent message", "message was OMEMO-encrypted despite disable");
    }

    /* Now test receiving: bob sends to alice — bob's side is NOT disabled,
     * so the message should be encrypted. Alice should still decrypt it
     * since receiving always decrypts regardless of blacklist. */
    reset_phase_counters();
    fprintf(stderr, "[harness] bob sending encrypted message to alice "
                    "(alice has OMEMO disabled for bob)...\n");
    await_messages(S.alice, MSG_DISABLED_RECV, 1, api_disable_recv_check, 10000);
    send_im(S.bob, "alice@localhost", MSG_DISABLED_RECV);
    return FALSE;
}

/* Asserts that alice decrypted bob's encrypted message even though
 * her OMEMO is disabled for him; the disable flag controls sending,
 * not receiving. */
static gboolean api_disable_recv_check(gpointer data) {
    (void) data;

    /* bob's lurch ISN'T disabled, so his outgoing must be encrypted
     * (plaintext absent from his wire), and alice must decrypt it. */
    if (S.sent_text && strstr(S.sent_text, MSG_DISABLED_RECV)) {
        test_fail("disabled: incoming message", "bob did not encrypt (unexpected)");
    } else if (S.wait.got < 1) {
        test_fail("disabled: incoming message", "alice did not decrypt");
    } else {
        test_pass("disabled: incoming encrypted message still decrypted");
    }

    next_phase();
    return FALSE;
}

/* ================================================================
 * Phase: re-enable OMEMO via API
 * ================================================================ */

static gboolean api_reenable_step2(gpointer data);
static gboolean api_reenable_step3(gpointer data);
static gboolean api_reenable_check(gpointer data);

/* First step of the re-enable phase: emits the enable signal. */
static gboolean api_reenable_step1(gpointer data) {
    (void) data;
    fprintf(stderr, "\n--- phase: re-enable OMEMO via API ---\n");
    fprintf(stderr, "[harness] re-enabling OMEMO for bob via API...\n");

    api_called = FALSE;
    purple_signal_emit(purple_plugins_get_handle(), "lurch-enable-im",
                       S.alice, "bob@localhost",
                       api_enable_disable_cb, NULL);

    g_idle_add(api_reenable_step2, NULL);
    return FALSE;
}

/* Asserts enable callback success, then queries status to confirm. */
static gboolean api_reenable_step2(gpointer data) {
    (void) data;

    if (api_called && api_err == 0) {
        test_pass("re-enable OMEMO via API succeeded");
    } else {
        test_fail("re-enable OMEMO via API", "callback error");
    }

    /* Check status is back to OK */
    api_called = FALSE;
    purple_signal_emit(purple_plugins_get_handle(), "lurch-status-im",
                       S.alice, "bob@localhost",
                       api_status_im_cb, NULL);

    g_idle_add(api_reenable_step3, NULL);
    return FALSE;
}

/* Asserts status is back to OK, then sends a message to confirm
 * messaging actually works again end-to-end. */
static gboolean api_reenable_step3(gpointer data) {
    (void) data;

    if (api_called && api_err == 0 && api_status == LURCH_STATUS_OK) {
        test_pass("OMEMO status is OK after re-enable");
    } else {
        char reason[128];
        snprintf(reason, sizeof(reason), "cb=%d err=%d status=%d",
                 api_called, api_err, api_status);
        test_fail("OMEMO status after re-enable", reason);
    }

    /* Send a message to confirm it works again */
    reset_phase_counters();
    fprintf(stderr, "[harness] sending message after re-enable...\n");
    await_messages(S.bob, MSG_AFTER_ENABLE, 1, api_reenable_check, 10000);
    send_im(S.alice, "bob@localhost", MSG_AFTER_ENABLE);
    return FALSE;
}

/* Final assertion for the re-enable phase: post-enable round-trip
 * encrypted and delivered. */
static gboolean api_reenable_check(gpointer data) {
    (void) data;

    if (S.sent_text && strstr(S.sent_text, MSG_AFTER_ENABLE)) {
        test_fail("message after re-enable", "plaintext on the wire");
    } else if (S.wait.got < 1) {
        test_fail("message after re-enable", "not received");
    } else {
        test_pass("message works after re-enable");
    }

    next_phase();
    return FALSE;
}

/* ================================================================
 * Phase: multibyte UTF-8 message
 * ================================================================ */

static gboolean utf8_msg_check(gpointer data);

/* Sends a message with multibyte UTF-8 (accented Latin plus a
 * check mark) to confirm the encrypt/decrypt path doesn't mangle
 * non-ASCII bytes. Plain XML-special chars are skipped because
 * libpurple HTML-escapes them on display, masking the test. */
static gboolean utf8_msg_start(gpointer data) {
    (void) data;
    fprintf(stderr, "\n--- phase: multibyte UTF-8 message ---\n");
    fprintf(stderr, "[harness] sending message with multibyte UTF-8...\n");
    await_messages(S.bob, MSG_UTF8, 1, utf8_msg_check, 10000);
    send_im(S.alice, "bob@localhost", MSG_UTF8);
    return FALSE;
}

/* Verifies the UTF-8 payload round-tripped intact (and was encrypted
 * on the wire). */
static gboolean utf8_msg_check(gpointer data) {
    (void) data;

    if (S.sent_text && strstr(S.sent_text, MSG_UTF8)) {
        test_fail("UTF-8 message", "plaintext on the wire");
    } else if (S.wait.got < 1) {
        test_fail("UTF-8 message", "content mangled or not received");
    } else {
        test_pass("UTF-8 message: encrypted and round-tripped");
    }

    next_phase();
    return FALSE;
}

/* ================================================================
 * Phase: offline message
 * ================================================================ */

static gboolean offline_send_and_check(gpointer data);

/* Entry point for the offline-message phase. Snapshots bob's device
 * IDs as lurch currently knows them (so the reconnect phase has
 * something to diff against), then disables bob's account. The send
 * step polls for the disconnect to actually complete and then runs
 * the check inline (no incoming side to wait for). */
static gboolean offline_start(gpointer data) {
    (void) data;
    fprintf(stderr, "\n--- phase: message to offline bob ---\n");

    purple_signal_emit(purple_plugins_get_handle(), "lurch-fp-other",
                       S.alice, "bob@localhost",
                       snapshot_bob_devices_cb, NULL);

    fprintf(stderr, "[harness] disconnecting bob...\n");
    purple_account_set_enabled(S.bob, "lurch-integration-test", FALSE);

    g_idle_add(offline_send_and_check, NULL);
    return FALSE;
}

/* Polls for bob's account to actually be signed off, then sends and
 * runs the assertion synchronously: xml_sent_cb fires inside send_im
 * so the sent-stanza state is already populated by the time we
 * inspect it. Checking only "plaintext absent" would pass vacuously
 * when no stanza was emitted at all, so this also requires that a
 * message stanza left the wire and that it carried an OMEMO
 * <encrypted> element. */
static gboolean offline_send_and_check(gpointer data) {
    (void) data;

    if (S.bob_connected) {
        fprintf(stderr, "[harness] bob not yet disconnected, waiting...\n");
        g_timeout_add(200, offline_send_and_check, NULL);
        return FALSE;
    }

    fprintf(stderr, "[harness] sending message to offline bob...\n");
    send_im(S.alice, "bob@localhost", MSG_OFFLINE);

    if (S.sent_msg_count < 1) {
        test_fail("offline message", "no message stanza observed on the wire");
    } else if (S.sent_text && strstr(S.sent_text, MSG_OFFLINE)) {
        test_fail("offline message", "plaintext leaked in outgoing stanza");
    } else if (!S.sent_encrypted) {
        test_fail("offline message", "stanza sent without OMEMO <encrypted> element");
    } else {
        test_pass("offline message: encrypted, no plaintext leaked");
    }

    next_phase();
    return FALSE;
}

/* ================================================================
 * Phase: reconnect bob
 * ================================================================ */

static gboolean reconnect_send(gpointer data);
static gboolean reconnect_check(gpointer data);

/* Re-enables bob's account so libpurple reconnects him. Sets the
 * bob_reconnecting flag so account_signed_on knows to take the
 * "already-online dance, skip the initial connect_alice timer" path. */
static gboolean reconnect_start(gpointer data) {
    (void) data;
    fprintf(stderr, "\n--- phase: reconnect bob ---\n");
    fprintf(stderr, "[harness] reconnecting bob...\n");

    S.bob_reconnecting = TRUE;
    purple_account_set_enabled(S.bob, "lurch-integration-test", TRUE);

    g_idle_add(reconnect_send, NULL);
    return FALSE;
}

/* Polls for bob's reconnection completing. Sends as soon as bob is
 * back online — no upfront wall-clock guess at how long the reconnect
 * takes; just self-reschedules every 500ms while we wait. */
static gboolean reconnect_send(gpointer data) {
    (void) data;

    if (!S.bob_connected) {
        g_timeout_add(500, reconnect_send, NULL);
        return FALSE;
    }

    fprintf(stderr, "[harness] sending message after reconnect...\n");
    await_messages(S.bob, MSG_RECONNECT, 1, reconnect_check, 15000);
    send_im(S.alice, "bob@localhost", MSG_RECONNECT);
    return FALSE;
}

/* Final step of the reconnect phase: asserts the round-trip worked
 * after bob reconnected, then emits lurch-fp-other so the stability
 * callback can diff the post-reconnect devicelist against the
 * snapshot taken in offline_start, and checks that the server still
 * lists exactly bob's two devices. */
static gboolean reconnect_check(gpointer data) {
    (void) data;

    if (S.sent_text && strstr(S.sent_text, MSG_RECONNECT)) {
        test_fail("reconnect", "plaintext on the wire");
    } else if (S.wait.got < 1) {
        test_fail("reconnect", "bob did not receive message");
    } else {
        test_pass("reconnect: encrypted message received");
    }

    purple_signal_emit(purple_plugins_get_handle(), "lurch-fp-other",
                       S.alice, "bob@localhost",
                       check_bob_stability_cb, NULL);

    assert_server_devicelist("server: bob's devicelist unchanged after reconnect",
                             BOB_JID "@" XMPP_SERVER, bob_server_ids, 2);

    next_phase();
    return FALSE;
}

/* ================================================================
 * Phase: non-OMEMO peer
 * ================================================================ */

/* Sends a message to charlie (configured to NOT be an OMEMO user) and
 * asserts inline that lurch sent it in the clear. charlie isn't in
 * this process so there's no incoming side to wait for — and we don't
 * need one: send_im's signal pipeline is synchronous, so S.sent_text
 * is populated by the time send_im returns. */
static gboolean no_omemo_start(gpointer data) {
    (void) data;
    fprintf(stderr, "\n--- phase: message to non-OMEMO peer ---\n");
    fprintf(stderr, "[harness] sending message to charlie (no OMEMO)...\n");
    send_im(S.alice, "charlie@localhost", MSG_NO_OMEMO);

    /* Expecting plaintext for a non-OMEMO peer — MSG_NO_OMEMO should
     * appear on the wire. */
    if (S.sent_text && strstr(S.sent_text, MSG_NO_OMEMO)) {
        test_pass("no-OMEMO peer: message not OMEMO-encrypted");
    } else {
        test_fail("no-OMEMO peer",
                  "message was OMEMO-encrypted for peer without device list");
    }

    next_phase();
    return FALSE;
}

/* ================================================================
 * Scenario registry
 * ================================================================ */

static const PhaseFunc smoke_phases[] = {
    alice_bob_start,
    bob_alice_start,
    multi_msg_start,
    multi_device_start,
    api_disable_step1,
    api_reenable_step1,
    utf8_msg_start,
    offline_start,
    reconnect_start,
    no_omemo_start,
};

/* Baseline message first (sessions with bob's only device), then the
 * second device appears, then a message must reach both devices. */
static const PhaseFunc devicelist_update_phases[] = {
    alice_bob_start,
    dl_update_start,
    multi_device_start,
};

static const Scenario scenarios[] = {
    {
        .name = "smoke",
        .description = "normal operation: messaging, multi-device, API, "
                       "offline/reconnect, non-OMEMO peer",
        .dev2 = DEV2_AT_START,
        .phases = smoke_phases,
        .n_phases = G_N_ELEMENTS(smoke_phases),
    },
    {
        .name = "devicelist-update",
        .description = "bob's second device comes online while alice is "
                       "connected; alice must receive and use the update",
        .dev2 = DEV2_ON_DEMAND,
        .phases = devicelist_update_phases,
        .n_phases = G_N_ELEMENTS(devicelist_update_phases),
    },
};

/* Looks up a scenario by name; NULL if there is none. */
const Scenario *scenario_find(const char *name) {
    for (gsize i = 0; i < G_N_ELEMENTS(scenarios); i++) {
        if (strcmp(scenarios[i].name, name) == 0) {
            return &scenarios[i];
        }
    }
    return NULL;
}

/* Prints one scenario name per line (stdout: for run.sh to iterate),
 * with the description after a tab. */
void scenario_list(FILE *out) {
    for (gsize i = 0; i < G_N_ELEMENTS(scenarios); i++) {
        fprintf(out, "%s\t%s\n", scenarios[i].name, scenarios[i].description);
    }
}

/* ================================================================
 * Phase dispatcher
 * ================================================================ */

/* Called by next_phase via a GLib timer: runs the current phase of the
 * selected scenario (which chains its own steps and ultimately calls
 * next_phase again), or finishes once all phases have run. */
gboolean run_phase(gpointer data) {
    (void) data;

    if (S.phase >= S.scenario->n_phases) {
        finish_tests();
        return FALSE;
    }
    S.scenario->phases[S.phase](NULL);
    return FALSE;
}
