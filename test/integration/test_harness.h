/*
 * Integration test harness for lurch OMEMO plugin — shared definitions.
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>

#include <glib.h>
#include <poll.h>
#include <purple.h>

#include "lurch_api.h"

#define TEST_USER_DIR      "/tmp/lurch_integration_test"
#define TEST_USER_DIR_DEV2 "/tmp/lurch_integration_test_dev2"
#define ALICE_JID          "alice"
#define ALICE_PASS         "testpass_alice"
#define BOB_JID            "bob"
#define BOB_PASS           "testpass_bob"
#define CHARLIE_JID        "charlie"
#define XMPP_SERVER        "localhost"
#define XMPP_PORT_DEFAULT  5222
#define OMEMO_NS           "eu.siacs.conversations.axolotl"
#define JABBER_PROTOCOL_ID "prpl-jabber"

#define TEST_TIMEOUT_S     180
/* The child must outlive the parent's suite deadline: if it quits
 * first, later pipe writes would hit a dead peer (see SIGPIPE
 * handling in main). */
#define CHILD_TIMEOUT_S    (TEST_TIMEOUT_S + 30)
/* Parent-side cap on waiting for the child's READY handshake; keeps
 * a wedged child from hanging the suite before the watchdog exists. */
#define READY_TIMEOUT_MS   30000
/* Fallback delays only — the primary triggers are event-driven
 * (devicelist PEP events; see xml_recv_cb). */
#define SEND_DELAY_MS      8000
#define PHASE_DELAY_MS     1000
#define MULTI_MSG_COUNT    3

/* Test message strings */
#define MSG_ALICE_BOB     "Hello Bob, this is a secret OMEMO message!"
#define MSG_BOB_ALICE     "Hey Alice, got your message!"
#define MSG_MULTI_FMT     "Multi message #%d from alice"
#define MSG_DISABLED_SEND "Message while OMEMO disabled for bob"
#define MSG_DISABLED_RECV "Encrypted msg from bob while disabled"
#define MSG_AFTER_ENABLE  "Message after re-enabling OMEMO"
#define MSG_OFFLINE       "Message while bob is offline"
#define MSG_RECONNECT     "Message after bob reconnected"
#define MSG_NO_OMEMO      "Message to non-OMEMO charlie"
#define MSG_MULTI_DEV     "Message for multi-device test"
#define MSG_UTF8          "test: caf\xc3\xa9 \xc3\xbc\xc3\xb6\xc3\xa4 \xe2\x9c\x93"

/* A phase entry point. Each phase chains its own steps on GLib timers
 * and finally calls next_phase(). */
typedef gboolean (*PhaseFunc)(gpointer data);

/* When (if at all) a scenario needs bob's second device. The child is
 * always forked before libpurple init in the parent (a fork after init
 * would share libpurple state); ON_DEMAND children just wait for a
 * CONNECT command before signing in. */
typedef enum {
    DEV2_NONE = 0,
    DEV2_AT_START,               /* online and published before bob/alice connect */
    DEV2_ON_DEMAND,              /* signs in when a phase calls second_device_connect */
} Dev2Mode;

/* A named, independently runnable sequence of phases. run.sh starts a
 * fresh Prosody container and fresh user dirs for every scenario, so
 * a scenario can rely on a clean server state and can't leak broken
 * state into the next one. */
typedef struct {
    const char *name;
    const char *description;
    Dev2Mode dev2;
    const PhaseFunc *phases;
    int n_phases;
} Scenario;

/* One item of a PEP devicelist node as Prosody stores it. */
typedef struct {
    char *id;                    /* pubsub item id */
    GList *device_ids;           /* uint32_t *, in document order */
} ServerItem;

/* The single in-flight wait for incoming-message events. A phase sets
 * recv/expected_text/wanted to describe what it's looking for, arms
 * on_done + a fallback timeout, and either conv_write_im (on match) or
 * the timeout source fires on_done exactly once. on_done is NULLed on
 * fire, which doubles as the "already fired" guard. */
typedef struct {
    PurpleAccount *recv;
    const char *expected_text;
    int wanted;
    int got;
    GSourceFunc on_done;
    guint timeout_id;
} PendingWait;

/* Forked second-device process (bob's second device). */
typedef struct {
    pid_t pid;
    int read_fd;                 /* parent reads from child */
    int write_fd;                /* parent writes to child */
    uint32_t device_id;          /* child's own OMEMO device ID (from READY) */
} ChildProc;

typedef struct {
    GMainLoop    *loop;
    PurplePlugin *lurch_plugin;
    PurplePlugin *carbons_plugin;

    PurpleAccount *alice;
    PurpleAccount *bob;
    gboolean alice_connected;
    gboolean bob_connected;
    gboolean bob_reconnecting;

    const Scenario *scenario;
    int phase;                   /* index into scenario->phases */
    gboolean phases_started;     /* one-shot latch around start_phases */

    /* bob's devicelist PEP events as alice receives them: how many
     * arrived, and the device IDs in the most recent one (uint32_t *).
     * Phases reset the counter to watch for a fresh update. */
    int alice_bob_dl_events;
    GList *alice_bob_dl_ids;
    int tests_passed;
    int tests_failed;

    /* Every text node from every outgoing message stanza in the
     * current phase, concatenated and appended to as xml_sent_cb
     * fires. Phases grep this for the plaintext they tried to send:
     * absent = lurch encrypted (or didn't send), present = lurch
     * sent plaintext (intentionally for non-OMEMO peers, or
     * accidentally — a leak). Reset between phases.
     *
     * sent_text alone can't distinguish "encrypted" from "never
     * sent", so sent_msg_count / sent_encrypted track how many
     * message stanzas actually left in this phase and whether any
     * carried an OMEMO <encrypted> element. */
    char *sent_text;
    int sent_msg_count;
    gboolean sent_encrypted;
    PendingWait wait;
    ChildProc child;
} TestState;

extern TestState S;

/* Helpers (defined in test_harness.c) */
void test_pass(const char *name);
void test_fail(const char *name, const char *reason);
void reset_phase_counters(void);
void next_phase(void);
/* Send a message. xml_sent_cb fires synchronously from inside the
 * libpurple signal pipeline, so by the time this returns S.sent_text,
 * S.sent_msg_count and S.sent_encrypted reflect the final wire form
 * (after lurch's encryption pass) and outgoing-only phases can assert
 * on them immediately. */
PurpleConversation *send_im(PurpleAccount *from, const char *to, const char *msg);

/* Arms a wait for `count` incoming messages on `recv` matching
 * `expected_text`. on_done fires once when conv_write_im has seen
 * enough, or after timeout_ms if the messages never arrive (so the
 * phase still gets to run its assertion against the under-target
 * counter rather than hanging the suite).
 *
 * Phases that send AND await call this BEFORE send_im — arming first
 * means a fast local echo can satisfy the wait without a race. */
void await_messages(PurpleAccount *recv, const char *expected_text,
                    int count, GSourceFunc on_done, guint timeout_ms);
void finish_tests(void);
PurpleAccount *create_account(const char *user, const char *pass);
/* Reap the second-device child without risking an indefinite block:
 * polls waitpid(WNOHANG) for up to timeout_ms, then SIGKILLs. */
void reap_child(int timeout_ms);

/* Tells an ON_DEMAND second device to sign in. on_ready runs once from
 * the main loop: TRUE when the child reported READY (S.child.device_id
 * is then set), FALSE on timeout. */
void second_device_connect(void (*on_ready)(gboolean ok));

/* Returns TRUE if the most recent devicelist event alice received from
 * bob lists `id`. */
gboolean alice_saw_bob_device(uint32_t id);

/* Returns the account's own OMEMO device ID as lurch reports it via
 * lurch-id-list, or 0 if lurch doesn't list it (which is itself a
 * symptom of the devicelist bug). */
uint32_t own_device_id(PurpleAccount *acc);

/* Server-state inspection (defined in test_server.c). These read
 * Prosody's PEP storage directly, so assertions see what the server
 * stores rather than lurch's local cache of it. */
int server_devicelist_items(const char *bare_jid, GList **items_out);
void server_items_free(GList *items);
/* Asserts that bare_jid's devicelist node holds exactly one item, with
 * ID 'current', listing exactly the `n` IDs in `expected` (in any order). */
void assert_server_devicelist(const char *name, const char *bare_jid,
                              const uint32_t *expected, int n);

/* Scenario registry and phase dispatcher (defined in test_phases.c) */
const Scenario *scenario_find(const char *name);
void scenario_list(FILE *out);
gboolean run_phase(gpointer data);

#endif /* TEST_HARNESS_H */
