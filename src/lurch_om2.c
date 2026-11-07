#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <glib.h>
#include <purple.h>
#include <sqlite3.h>

#include "iq.h"
#include "jabber.h"
#include "jutil.h"
#include "pep.h"

#include "axc.h"
#include "axc_store.h"
#include "signal_protocol.h"

#include "lurch_om2.h"
#include "lurch_om2_crypto.h"
#include "lurch_om2_session.h"
#include "lurch_util.h"

#define LOG "lurch"

#define NS_OM2          LURCH_NS_OM2
#define NS_LEGACY       "eu.siacs.conversations.axolotl"
#define NODE_DEVICES    NS_OM2 ":devices"
#define NODE_BUNDLES    NS_OM2 ":bundles"
#define NS_SCE          "urn:xmpp:sce:1"
#define NS_HINTS        "urn:xmpp:hints"
#define NS_EME          "urn:xmpp:eme:0"
#define NS_PUBSUB       "http://jabber.org/protocol/pubsub"
#define NS_CLIENT       "jabber:client"

#define MAX_ID                INT32_MAX
#define PRE_KEYS_AMOUNT       100
#define SPK_ROTATION_SECONDS  (30 * 24 * 60 * 60)
#define RPAD_MAX_LEN          200

#define MSG_NOT_SENT          "There was an error encrypting the message and it was not sent. You can try again, or try to find the problem by looking at the debug log."
#define MSG_DECRYPT_FAILED    "There was an error decrypting an OMEMO 2 message addressed to this device. See the debug log for details."
#define MSG_NO_KEY            "Received an OMEMO 2 message that does not contain a key for this device."
#define MSG_IDENTITY_CHANGED  "The identity key of device %u of %s has changed, which might be an attack! Messages from and to it are refused. " \
                              "If you verified the new fingerprint, use '/lurch omemo2 reset' to accept it."

typedef struct {
  char * jid;
  uint32_t device_id;
} om2_target;

/** A message waiting for the bundles of all devices without a session. */
typedef struct {
  JabberStream * js_p;
  char * uname;
  char * recipient;
  xmlnode * stanza_p;
  char * body;
  GList * targets_p;
  int pending;
  gboolean must_reach_recipient;
} om2_queued_msg;

typedef struct {
  om2_queued_msg * qmsg_p;
  om2_target * target_p;
} om2_bundle_request;

/*
 * Storage
 */

static const char * const db_schema =
  "CREATE TABLE IF NOT EXISTS spk(id INTEGER PRIMARY KEY, priv BLOB NOT NULL, pub BLOB NOT NULL, sig BLOB NOT NULL, created INTEGER NOT NULL);"
  "CREATE TABLE IF NOT EXISTS pk(id INTEGER PRIMARY KEY, priv BLOB NOT NULL, pub BLOB NOT NULL);"
  "CREATE TABLE IF NOT EXISTS session(jid TEXT NOT NULL, device INTEGER NOT NULL, state BLOB NOT NULL, PRIMARY KEY(jid, device));"
  "CREATE TABLE IF NOT EXISTS device(jid TEXT NOT NULL, device INTEGER NOT NULL, PRIMARY KEY(jid, device));"
  "CREATE TABLE IF NOT EXISTS identity(jid TEXT NOT NULL, device INTEGER NOT NULL, ik BLOB NOT NULL, PRIMARY KEY(jid, device));";

static sqlite3 * db_open(const char * uname) {
  sqlite3 * db_p = (void *) 0;
  char * fn = lurch_util_uname_get_db_fn(uname, LURCH_DB_NAME_OM2);
  int ret_val = sqlite3_open(fn, &db_p);

  if (ret_val == SQLITE_OK) {
    // this contains private keys
    (void) chmod(fn, S_IRUSR | S_IWUSR);
    sqlite3_busy_timeout(db_p, 5000);
    ret_val = sqlite3_exec(db_p, db_schema, (void *) 0, (void *) 0, (void *) 0);
  }

  if (ret_val != SQLITE_OK) {
    purple_debug_error(LOG, "%s: failed to open %s: %s\n", __func__, fn, db_p ? sqlite3_errmsg(db_p) : "(no db)");
    sqlite3_close(db_p);
    db_p = (void *) 0;
  }

  g_free(fn);
  return db_p;
}

static sqlite3_stmt * db_prepare(sqlite3 * db_p, const char * sql) {
  sqlite3_stmt * stmt_p = (void *) 0;

  if (sqlite3_prepare_v2(db_p, sql, -1, &stmt_p, (void *) 0) != SQLITE_OK) {
    purple_debug_error(LOG, "%s: failed to prepare '%s': %s\n", __func__, sql, sqlite3_errmsg(db_p));
    return (void *) 0;
  }

  return stmt_p;
}

static gboolean db_blob_get(sqlite3_stmt * stmt_p, int col, uint8_t * out_p, int len) {
  if (sqlite3_column_bytes(stmt_p, col) != len) {
    return FALSE;
  }

  memcpy(out_p, sqlite3_column_blob(stmt_p, col), len);
  return TRUE;
}

/** @return The IDs on the stored devicelist, as GUINT_TO_POINTER. */
static GList * db_devices_get(sqlite3 * db_p, const char * jid) {
  GList * ids_p = (void *) 0;
  sqlite3_stmt * stmt_p = db_prepare(db_p, "SELECT device FROM device WHERE jid = ?1;");

  if (stmt_p) {
    sqlite3_bind_text(stmt_p, 1, jid, -1, SQLITE_STATIC);
    while (sqlite3_step(stmt_p) == SQLITE_ROW) {
      ids_p = g_list_prepend(ids_p, GUINT_TO_POINTER((guint) sqlite3_column_int64(stmt_p, 0)));
    }
  }

  sqlite3_finalize(stmt_p);
  return ids_p;
}

static void db_devices_set(sqlite3 * db_p, const char * jid, GList * ids_p) {
  sqlite3_stmt * stmt_p = db_prepare(db_p, "DELETE FROM device WHERE jid = ?1;");

  sqlite3_exec(db_p, "BEGIN;", (void *) 0, (void *) 0, (void *) 0);

  if (stmt_p) {
    sqlite3_bind_text(stmt_p, 1, jid, -1, SQLITE_STATIC);
    sqlite3_step(stmt_p);
    sqlite3_finalize(stmt_p);
  }

  stmt_p = db_prepare(db_p, "INSERT OR IGNORE INTO device(jid, device) VALUES(?1, ?2);");
  if (stmt_p) {
    for (GList * curr_p = ids_p; curr_p; curr_p = curr_p->next) {
      sqlite3_bind_text(stmt_p, 1, jid, -1, SQLITE_STATIC);
      sqlite3_bind_int64(stmt_p, 2, GPOINTER_TO_UINT(curr_p->data));
      sqlite3_step(stmt_p);
      sqlite3_reset(stmt_p);
    }
    sqlite3_finalize(stmt_p);
  }

  sqlite3_exec(db_p, "COMMIT;", (void *) 0, (void *) 0, (void *) 0);
}

static lurch_om2_session * db_session_get(sqlite3 * db_p, const char * jid, uint32_t device_id) {
  lurch_om2_session * session_p = (void *) 0;
  sqlite3_stmt * stmt_p = db_prepare(db_p, "SELECT state FROM session WHERE jid = ?1 AND device = ?2;");

  if (stmt_p) {
    sqlite3_bind_text(stmt_p, 1, jid, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt_p, 2, device_id);
    if (sqlite3_step(stmt_p) == SQLITE_ROW
        && lurch_om2_session_deserialize(sqlite3_column_blob(stmt_p, 0), sqlite3_column_bytes(stmt_p, 0), &session_p)) {
      purple_debug_error(LOG, "%s: stored session with %s:%u is corrupt\n", __func__, jid, device_id);
      session_p = (void *) 0;
    }
  }

  sqlite3_finalize(stmt_p);
  return session_p;
}

static int db_session_set(sqlite3 * db_p, const char * jid, uint32_t device_id, const lurch_om2_session * session_p) {
  uint8_t * state_p = (void *) 0;
  size_t state_len = 0;
  int ret_val = -1;
  sqlite3_stmt * stmt_p = db_prepare(db_p, "INSERT OR REPLACE INTO session(jid, device, state) VALUES(?1, ?2, ?3);");

  if (stmt_p && !lurch_om2_session_serialize(session_p, &state_p, &state_len)) {
    sqlite3_bind_text(stmt_p, 1, jid, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt_p, 2, device_id);
    sqlite3_bind_blob(stmt_p, 3, state_p, (int) state_len, SQLITE_STATIC);
    if (sqlite3_step(stmt_p) == SQLITE_DONE) {
      ret_val = 0;
    }
  }

  sqlite3_finalize(stmt_p);
  if (state_p) {
    lurch_om2_wipe(state_p, state_len);
    g_free(state_p);
  }
  return ret_val;
}

/**
 * Trust on first use: the first identity key seen for a device is remembered, using db_identity_remember().
 * Checking does not remember anything: an unauthenticated message must not be able to decide which key is trusted.
 *
 * @return 1 if the key is the known one or there is none yet, 0 if the known one is different, negative on error.
 */
static int db_identity_check(sqlite3 * db_p, const char * jid, uint32_t device_id, const uint8_t * ik_p) {
  uint8_t known[LURCH_OM2_KEY_LEN];
  int ret_val = -1;
  sqlite3_stmt * stmt_p = db_prepare(db_p, "SELECT ik FROM identity WHERE jid = ?1 AND device = ?2;");

  if (!stmt_p) {
    return -1;
  }

  sqlite3_bind_text(stmt_p, 1, jid, -1, SQLITE_STATIC);
  sqlite3_bind_int64(stmt_p, 2, device_id);

  switch (sqlite3_step(stmt_p)) {
    case SQLITE_ROW:
      if (db_blob_get(stmt_p, 0, known, sizeof(known))) {
        ret_val = lurch_om2_equal(known, ik_p, sizeof(known)) ? 1 : 0;
      }
      break;
    case SQLITE_DONE:
      ret_val = 1;
      break;
    default:
      break;
  }

  sqlite3_finalize(stmt_p);
  return ret_val;
}

/** Remembers an identity key, unless there already is one. Only use this for authenticated keys. */
static int db_identity_remember(sqlite3 * db_p, const char * jid, uint32_t device_id, const uint8_t * ik_p) {
  int ret_val = -1;
  sqlite3_stmt * stmt_p = db_prepare(db_p, "INSERT OR IGNORE INTO identity(jid, device, ik) VALUES(?1, ?2, ?3);");

  if (stmt_p) {
    sqlite3_bind_text(stmt_p, 1, jid, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt_p, 2, device_id);
    sqlite3_bind_blob(stmt_p, 3, ik_p, LURCH_OM2_KEY_LEN, SQLITE_STATIC);
    ret_val = sqlite3_step(stmt_p) == SQLITE_DONE ? 0 : -1;
  }

  sqlite3_finalize(stmt_p);
  return ret_val;
}

/** Loads the identity key pair that is shared with the old version. */
static int own_identity_get(const char * uname, lurch_om2_keypair * ik_p, uint32_t * device_id_p) {
  axc_context * axc_ctx_p = (void *) 0;
  signal_buffer * pub_p = (void *) 0;
  signal_buffer * priv_p = (void *) 0;
  int ret_val = -1;
  char * uname_copy = g_strdup(uname);

  if (lurch_util_axc_get_init_ctx(uname_copy, &axc_ctx_p)
      || axc_db_identity_get_key_pair(&pub_p, &priv_p, axc_ctx_p) != 0
      || axc_get_device_id(axc_ctx_p, device_id_p)) {
    purple_debug_error(LOG, "%s: failed to load the identity of %s\n", __func__, uname);
    goto cleanup;
  }

  // the public key is prefixed with the key type
  if (signal_buffer_len(pub_p) != LURCH_OM2_KEY_LEN + 1 || signal_buffer_len(priv_p) != LURCH_OM2_KEY_LEN) {
    purple_debug_error(LOG, "%s: unexpected key format\n", __func__);
    goto cleanup;
  }

  memcpy(ik_p->pub, signal_buffer_data(pub_p) + 1, LURCH_OM2_KEY_LEN);
  memcpy(ik_p->priv, signal_buffer_data(priv_p), LURCH_OM2_KEY_LEN);
  ret_val = 0;

cleanup:
  signal_buffer_bzero_free(priv_p);
  signal_buffer_free(pub_p);
  axc_context_destroy_all(axc_ctx_p);
  g_free(uname_copy);
  return ret_val;
}

/** Loads just the device ID, which is shared with the old version. */
static int own_device_id_get(const char * uname, uint32_t * device_id_p) {
  axc_context * axc_ctx_p = (void *) 0;
  char * uname_copy = g_strdup(uname);
  int ret_val = 0;

  if (lurch_util_axc_get_init_ctx(uname_copy, &axc_ctx_p) || axc_get_device_id(axc_ctx_p, device_id_p)) {
    purple_debug_error(LOG, "%s: failed to load the device ID of %s\n", __func__, uname);
    ret_val = -1;
  }

  axc_context_destroy_all(axc_ctx_p);
  g_free(uname_copy);
  return ret_val;
}

static gint64 db_next_id(sqlite3 * db_p, const char * sql) {
  gint64 id = 1;
  sqlite3_stmt * stmt_p = db_prepare(db_p, sql);

  if (stmt_p && sqlite3_step(stmt_p) == SQLITE_ROW) {
    id = sqlite3_column_int64(stmt_p, 0) + 1;
  }

  sqlite3_finalize(stmt_p);
  return id > MAX_ID ? 1 : id;
}

static int spk_generate(sqlite3 * db_p, const lurch_om2_keypair * ik_p) {
  lurch_om2_keypair spk;
  uint8_t sig[LURCH_OM2_SIG_LEN];
  int ret_val = -1;
  sqlite3_stmt * stmt_p = (void *) 0;

  if (lurch_om2_x25519_generate(&spk) || lurch_om2_xeddsa_sign(ik_p->priv, spk.pub, sizeof(spk.pub), sig)) {
    goto cleanup;
  }

  stmt_p = db_prepare(db_p, "INSERT OR REPLACE INTO spk(id, priv, pub, sig, created) VALUES(?1, ?2, ?3, ?4, ?5);");
  if (!stmt_p) {
    goto cleanup;
  }

  sqlite3_bind_int64(stmt_p, 1, db_next_id(db_p, "SELECT COALESCE(MAX(id), 0) FROM spk;"));
  sqlite3_bind_blob(stmt_p, 2, spk.priv, sizeof(spk.priv), SQLITE_STATIC);
  sqlite3_bind_blob(stmt_p, 3, spk.pub, sizeof(spk.pub), SQLITE_STATIC);
  sqlite3_bind_blob(stmt_p, 4, sig, sizeof(sig), SQLITE_STATIC);
  sqlite3_bind_int64(stmt_p, 5, (sqlite3_int64) time((void *) 0));
  ret_val = sqlite3_step(stmt_p) == SQLITE_DONE ? 0 : -1;

cleanup:
  sqlite3_finalize(stmt_p);
  lurch_om2_wipe(&spk, sizeof(spk));
  return ret_val;
}

/** Generates a signed PreKey if necessary, and drops those which are not needed for delayed messages any more. */
static int spk_maintain(sqlite3 * db_p, const lurch_om2_keypair * ik_p) {
  gint64 now = (gint64) time((void *) 0);
  gint64 newest = 0;
  sqlite3_stmt * stmt_p = db_prepare(db_p, "SELECT COALESCE(MAX(created), 0) FROM spk;");

  if (!stmt_p) {
    return -1;
  }
  if (sqlite3_step(stmt_p) == SQLITE_ROW) {
    newest = sqlite3_column_int64(stmt_p, 0);
  }
  sqlite3_finalize(stmt_p);

  if (now - newest >= SPK_ROTATION_SECONDS && spk_generate(db_p, ik_p)) {
    return -1;
  }

  stmt_p = db_prepare(db_p, "DELETE FROM spk WHERE created < ?1 AND id NOT IN (SELECT id FROM spk ORDER BY created DESC, id DESC LIMIT 2);");
  if (stmt_p) {
    sqlite3_bind_int64(stmt_p, 1, now - 2 * SPK_ROTATION_SECONDS);
    sqlite3_step(stmt_p);
    sqlite3_finalize(stmt_p);
  }

  return 0;
}

static int pk_replenish(sqlite3 * db_p) {
  int count = 0;
  int ret_val = 0;
  sqlite3_stmt * stmt_p = db_prepare(db_p, "SELECT COUNT(*) FROM pk;");

  if (!stmt_p) {
    return -1;
  }
  if (sqlite3_step(stmt_p) == SQLITE_ROW) {
    count = sqlite3_column_int(stmt_p, 0);
  }
  sqlite3_finalize(stmt_p);

  stmt_p = db_prepare(db_p, "INSERT INTO pk(id, priv, pub) VALUES(?1, ?2, ?3);");
  if (!stmt_p) {
    return -1;
  }

  sqlite3_exec(db_p, "BEGIN;", (void *) 0, (void *) 0, (void *) 0);
  gint64 next_id = db_next_id(db_p, "SELECT COALESCE(MAX(id), 0) FROM pk;");
  for (; count < PRE_KEYS_AMOUNT && !ret_val; count++) {
    lurch_om2_keypair pk;

    ret_val = lurch_om2_x25519_generate(&pk);
    if (!ret_val) {
      sqlite3_bind_int64(stmt_p, 1, next_id++);
      sqlite3_bind_blob(stmt_p, 2, pk.priv, sizeof(pk.priv), SQLITE_TRANSIENT);
      sqlite3_bind_blob(stmt_p, 3, pk.pub, sizeof(pk.pub), SQLITE_TRANSIENT);
      ret_val = sqlite3_step(stmt_p) == SQLITE_DONE ? 0 : -1;
      sqlite3_reset(stmt_p);
    }
    lurch_om2_wipe(&pk, sizeof(pk));
  }
  sqlite3_exec(db_p, ret_val ? "ROLLBACK;" : "COMMIT;", (void *) 0, (void *) 0, (void *) 0);

  sqlite3_finalize(stmt_p);
  return ret_val;
}

/*
 * XML helpers
 */

static void node_set_b64(xmlnode * node_p, const uint8_t * data_p, size_t len) {
  gchar * b64 = g_base64_encode(data_p, len);

  xmlnode_insert_data(node_p, b64, -1);
  g_free(b64);
}

/** @return The decoded content. g_free() when done. */
static uint8_t * node_get_b64(const xmlnode * node_p, gsize * len_p) {
  char * data = xmlnode_get_data(node_p);
  uint8_t * out_p = (void *) 0;

  *len_p = 0;
  if (data) {
    out_p = g_base64_decode(data, len_p);
    g_free(data);
  }

  return out_p;
}

/** Reads the content of an element which must have exactly this length. */
static gboolean node_get_b64_exact(const xmlnode * node_p, uint8_t * out_p, gsize len) {
  gsize actual_len = 0;
  uint8_t * data_p = node_p ? node_get_b64(node_p, &actual_len) : (void *) 0;
  gboolean ok = data_p && actual_len == len;

  if (ok) {
    memcpy(out_p, data_p, len);
  }

  g_free(data_p);
  return ok;
}

/** Parses an ID, which has to be between 1 and 2^31 - 1. */
static gboolean id_parse(const char * str, uint32_t * id_p) {
  guint64 value = 0;

  if (!str || !g_ascii_string_to_unsigned(str, 10, 1, MAX_ID, &value, (void *) 0)) {
    return FALSE;
  }

  *id_p = (uint32_t) value;
  return TRUE;
}

/** @param ids_p The IDs as uint32_t *, like libomemo has them. */
static gboolean list_contains(GList * ids_p, uint32_t id) {
  for (GList * curr_p = ids_p; curr_p; curr_p = curr_p->next) {
    if (*((uint32_t *) curr_p->data) == id) {
      return TRUE;
    }
  }
  return FALSE;
}

static char * js_get_uname(JabberStream * js_p) {
  return lurch_util_uname_strip(purple_account_get_username(purple_connection_get_account(js_p->gc)));
}

/**
 * Shows an error in the conversation, opening it if necessary: purple_conv_present_error() does nothing without one.
 * An incoming message that cannot be read would go unnoticed otherwise, which is the case for a changed key as well.
 */
static void error_show(JabberStream * js_p, const char * bare_jid, const char * msg) {
  PurpleAccount * acc_p = purple_connection_get_account(js_p->gc);

  if (!purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY, bare_jid, acc_p)) {
    (void) purple_conversation_new(PURPLE_CONV_TYPE_IM, acc_p, bare_jid);
  }

  purple_conv_present_error(bare_jid, acc_p, msg);
}

/*
 * Publishing
 */

static void bundle_publish(JabberStream * js_p, sqlite3 * db_p, const lurch_om2_keypair * ik_p, uint32_t own_id) {
  uint8_t ik_ed[LURCH_OM2_KEY_LEN];
  uint8_t pub[LURCH_OM2_KEY_LEN];
  uint8_t sig[LURCH_OM2_SIG_LEN];
  char * id_str = (void *) 0;
  sqlite3_stmt * stmt_p = (void *) 0;
  xmlnode * publish_p = (void *) 0;
  xmlnode * bundle_p = (void *) 0;
  xmlnode * prekeys_p = (void *) 0;
  xmlnode * node_p = (void *) 0;
  int pk_count = 0;

  if (lurch_om2_curve_to_ed(ik_p->pub, ik_ed)) {
    return;
  }

  publish_p = xmlnode_new("publish");
  xmlnode_set_attrib(publish_p, "node", NODE_BUNDLES);
  node_p = xmlnode_new_child(publish_p, "item");
  id_str = g_strdup_printf("%u", own_id);
  xmlnode_set_attrib(node_p, "id", id_str);
  g_free(id_str);
  bundle_p = xmlnode_new_child(node_p, "bundle");
  xmlnode_set_namespace(bundle_p, NS_OM2);

  stmt_p = db_prepare(db_p, "SELECT id, pub, sig FROM spk ORDER BY created DESC, id DESC LIMIT 1;");
  if (!stmt_p
      || sqlite3_step(stmt_p) != SQLITE_ROW
      || !db_blob_get(stmt_p, 1, pub, sizeof(pub))
      || !db_blob_get(stmt_p, 2, sig, sizeof(sig))) {
    purple_debug_error(LOG, "%s: there is no signed PreKey\n", __func__);
    goto cleanup;
  }

  node_p = xmlnode_new_child(bundle_p, "spk");
  id_str = g_strdup_printf("%" G_GINT64_FORMAT, (gint64) sqlite3_column_int64(stmt_p, 0));
  xmlnode_set_attrib(node_p, "id", id_str);
  g_free(id_str);
  node_set_b64(node_p, pub, sizeof(pub));
  node_set_b64(xmlnode_new_child(bundle_p, "spks"), sig, sizeof(sig));
  node_set_b64(xmlnode_new_child(bundle_p, "ik"), ik_ed, sizeof(ik_ed));
  sqlite3_finalize(stmt_p);

  prekeys_p = xmlnode_new_child(bundle_p, "prekeys");
  stmt_p = db_prepare(db_p, "SELECT id, pub FROM pk ORDER BY id;");
  while (stmt_p && sqlite3_step(stmt_p) == SQLITE_ROW) {
    if (db_blob_get(stmt_p, 1, pub, sizeof(pub))) {
      node_p = xmlnode_new_child(prekeys_p, "pk");
      id_str = g_strdup_printf("%" G_GINT64_FORMAT, (gint64) sqlite3_column_int64(stmt_p, 0));
      xmlnode_set_attrib(node_p, "id", id_str);
      g_free(id_str);
      node_set_b64(node_p, pub, sizeof(pub));
      pk_count++;
    }
  }

  if (!pk_count) {
    purple_debug_error(LOG, "%s: there are no PreKeys\n", __func__);
    goto cleanup;
  }

  lurch_util_pep_publish_multi(js_p, publish_p);
  publish_p = (void *) 0;

cleanup:
  sqlite3_finalize(stmt_p);
  xmlnode_free(publish_p);
}

static void devicelist_publish(JabberStream * js_p, GList * ids_p) {
  xmlnode * publish_p = xmlnode_new("publish");
  xmlnode * item_p = xmlnode_new_child(publish_p, "item");
  xmlnode * devices_p = xmlnode_new_child(item_p, "devices");

  xmlnode_set_attrib(publish_p, "node", NODE_DEVICES);
  xmlnode_set_attrib(item_p, "id", "current");
  xmlnode_set_namespace(devices_p, NS_OM2);

  for (GList * curr_p = ids_p; curr_p; curr_p = curr_p->next) {
    char * id_str = g_strdup_printf("%u", GPOINTER_TO_UINT(curr_p->data));

    xmlnode_set_attrib(xmlnode_new_child(devices_p, "device"), "id", id_str);
    g_free(id_str);
  }

  lurch_util_pep_publish(js_p, publish_p);
}

/** @return The IDs in a received devicelist, as GUINT_TO_POINTER. */
static GList * devicelist_parse(xmlnode * items_p) {
  GList * ids_p = (void *) 0;
  xmlnode * item_p = items_p ? lurch_util_pep_item_current(items_p) : (void *) 0;
  xmlnode * devices_p = item_p ? xmlnode_get_child_with_namespace(item_p, "devices", NS_OM2) : (void *) 0;

  if (!devices_p) {
    return (void *) 0;
  }

  for (xmlnode * device_p = xmlnode_get_child(devices_p, "device"); device_p; device_p = xmlnode_get_next_twin(device_p)) {
    uint32_t id = 0;

    if (id_parse(xmlnode_get_attrib(device_p, "id"), &id) && !g_list_find(ids_p, GUINT_TO_POINTER(id))) {
      ids_p = g_list_prepend(ids_p, GUINT_TO_POINTER(id));
    }
  }

  return ids_p;
}

/** A JabberPEPHandler for both the notifications and the responses to requests. */
static void devicelist_handler(JabberStream * js_p, const char * from, xmlnode * items_p) {
  char * uname = js_get_uname(js_p);
  sqlite3 * db_p = (void *) 0;
  GList * ids_p = (void *) 0;

  // Without a sender, it comes from the own account. That is the case for responses to own requests on e.g. Prosody.
  if (!from) {
    from = uname;
  }

  // Failed requests say nothing new about the devices, so what is known stays. Only own devicelists can be fixed.
  if (!items_p && g_strcmp0(uname, from)) {
    goto cleanup;
  }

  db_p = db_open(uname);
  if (!db_p) {
    goto cleanup;
  }

  ids_p = devicelist_parse(items_p);

  if (!g_strcmp0(uname, from)) {
    uint32_t own_id = 0;

    if (own_device_id_get(uname, &own_id)) {
      goto cleanup;
    }

    if (!g_list_find(ids_p, GUINT_TO_POINTER(own_id))) {
      purple_debug_info(LOG, "%s: own ID is not on the OMEMO 2 devicelist, adding it\n", __func__);
      ids_p = g_list_prepend(ids_p, GUINT_TO_POINTER(own_id));
      devicelist_publish(js_p, ids_p);
    }
  }

  db_devices_set(db_p, from, ids_p);
  purple_debug_info(LOG, "%s: %s has %u devices using OMEMO 2\n", __func__, from, g_list_length(ids_p));

cleanup:
  g_list_free(ids_p);
  sqlite3_close(db_p);
  g_free(uname);
}

void lurch_om2_devicelist_request(JabberStream * js_p, const char * bare_jid) {
  lurch_util_pep_request_all_items(js_p, bare_jid, NODE_DEVICES, devicelist_handler);
}

void lurch_om2_account_connected(JabberStream * js_p) {
  char * uname = js_get_uname(js_p);
  sqlite3 * db_p = db_open(uname);
  lurch_om2_keypair ik;
  uint32_t own_id = 0;

  if (!db_p) {
    goto cleanup;
  }

  if (own_identity_get(uname, &ik, &own_id)) {
    goto cleanup;
  }

  if (spk_maintain(db_p, &ik) || pk_replenish(db_p)) {
    purple_debug_error(LOG, "%s: failed to generate keys\n", __func__);
  } else {
    bundle_publish(js_p, db_p, &ik, own_id);
    lurch_om2_devicelist_request(js_p, uname);
  }

  lurch_om2_wipe(&ik, sizeof(ik));

cleanup:
  sqlite3_close(db_p);
  g_free(uname);
}

void lurch_om2_init(void) {
  jabber_pep_register_handler(NODE_DEVICES, devicelist_handler);
}

static int db_count(const char * uname, const char * sql, const char * bare_jid) {
  sqlite3 * db_p = db_open(uname);
  sqlite3_stmt * stmt_p = db_p ? db_prepare(db_p, sql) : (void *) 0;
  int count = 0;

  if (stmt_p) {
    sqlite3_bind_text(stmt_p, 1, bare_jid, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt_p) == SQLITE_ROW) {
      count = sqlite3_column_int(stmt_p, 0);
    }
  }

  sqlite3_finalize(stmt_p);
  sqlite3_close(db_p);
  return count;
}

int lurch_om2_contact_available(const char * uname, const char * bare_jid) {
  return db_count(uname, "SELECT COUNT(*) FROM device WHERE jid = ?1;", bare_jid) > 0;
}

int lurch_om2_contact_has_session(const char * uname, const char * bare_jid) {
  return db_count(uname, "SELECT COUNT(*) FROM session WHERE jid = ?1;", bare_jid) > 0;
}

/*
 * Sending
 */

static void target_free(gpointer data_p) {
  om2_target * target_p = data_p;

  g_free(target_p->jid);
  g_free(target_p);
}

static void qmsg_free(om2_queued_msg * qmsg_p) {
  g_free(qmsg_p->uname);
  g_free(qmsg_p->recipient);
  xmlnode_free(qmsg_p->stanza_p);
  if (qmsg_p->body) {
    lurch_om2_wipe(qmsg_p->body, strlen(qmsg_p->body));
    g_free(qmsg_p->body);
  }
  g_list_free_full(qmsg_p->targets_p, target_free);
  g_free(qmsg_p);
}

/** Creates the plaintext envelope, see XEP-0420 and the profile in XEP-0384. */
static char * envelope_create(const char * uname, const char * body, int * len_p) {
  xmlnode * envelope_p = xmlnode_new("envelope");
  xmlnode * content_p = xmlnode_new_child(envelope_p, "content");
  xmlnode * body_p = xmlnode_new_child(content_p, "body");
  xmlnode * time_p = xmlnode_new_child(envelope_p, "time");
  uint8_t rpad_bytes[RPAD_MAX_LEN];
  uint8_t rpad_len_byte = 0;
  gchar * rpad = (void *) 0;
  char * xml = (void *) 0;
  GDateTime * now_p = g_date_time_new_now_utc();
  gchar * stamp = g_date_time_format(now_p, "%Y-%m-%dT%H:%M:%SZ");

  xmlnode_set_namespace(envelope_p, NS_SCE);
  xmlnode_set_namespace(body_p, NS_CLIENT);
  xmlnode_insert_data(body_p, body, -1);

  // the padding hides the length of the message, base64 keeps it valid XML
  lurch_om2_random(&rpad_len_byte, 1);
  lurch_om2_random(rpad_bytes, sizeof(rpad_bytes));
  rpad = g_base64_encode(rpad_bytes, rpad_len_byte % sizeof(rpad_bytes) + 1);
  xmlnode_insert_data(xmlnode_new_child(envelope_p, "rpad"), rpad, -1);

  xmlnode_set_attrib(time_p, "stamp", stamp);
  xmlnode_set_attrib(xmlnode_new_child(envelope_p, "from"), "jid", uname);

  xml = xmlnode_to_str(envelope_p, len_p);

  xmlnode_free(envelope_p);
  g_free(rpad);
  g_free(stamp);
  g_date_time_unref(now_p);
  return xml;
}

/**
 * Encrypts the key material for one device and adds it to the header.
 *
 * @return 0 on success.
 */
static int header_add_key(sqlite3 * db_p, xmlnode * header_p, GHashTable * keys_nodes_p, const om2_target * target_p, const uint8_t * plain_p, size_t plain_len) {
  lurch_om2_session * session_p = db_session_get(db_p, target_p->jid, target_p->device_id);
  uint8_t * ct_p = (void *) 0;
  size_t ct_len = 0;
  int is_kex = 0;
  int ret_val = -1;
  xmlnode * keys_p = (void *) 0;
  xmlnode * key_p = (void *) 0;
  char * id_str = (void *) 0;

  if (!session_p) {
    purple_debug_warning(LOG, "%s: no session with %s:%u, skipping it\n", __func__, target_p->jid, target_p->device_id);
    return -1;
  }

  if (db_identity_check(db_p, target_p->jid, target_p->device_id, lurch_om2_session_get_remote_ik(session_p)) != 1) {
    purple_debug_warning(LOG, "%s: the key of %s:%u is not the known one, skipping it\n", __func__, target_p->jid, target_p->device_id);
    goto cleanup;
  }

  if (lurch_om2_session_encrypt(session_p, plain_p, plain_len, &ct_p, &ct_len, &is_kex)) {
    purple_debug_error(LOG, "%s: failed to encrypt for %s:%u\n", __func__, target_p->jid, target_p->device_id);
    goto cleanup;
  }

  // the state has to be saved before sending, a chain key must never be used twice
  if (db_session_set(db_p, target_p->jid, target_p->device_id, session_p)) {
    purple_debug_error(LOG, "%s: failed to save the session with %s:%u\n", __func__, target_p->jid, target_p->device_id);
    goto cleanup;
  }

  keys_p = g_hash_table_lookup(keys_nodes_p, target_p->jid);
  if (!keys_p) {
    keys_p = xmlnode_new_child(header_p, "keys");
    xmlnode_set_attrib(keys_p, "jid", target_p->jid);
    g_hash_table_insert(keys_nodes_p, target_p->jid, keys_p);
  }

  key_p = xmlnode_new_child(keys_p, "key");
  id_str = g_strdup_printf("%u", target_p->device_id);
  xmlnode_set_attrib(key_p, "rid", id_str);
  g_free(id_str);
  if (is_kex) {
    xmlnode_set_attrib(key_p, "kex", "true");
  }
  node_set_b64(key_p, ct_p, ct_len);

  ret_val = 0;

cleanup:
  g_free(ct_p);
  lurch_om2_session_destroy(session_p);
  return ret_val;
}

/** Does the actual sending once there are sessions for all devices that could be reached. */
static void qmsg_finish(om2_queued_msg * qmsg_p) {
  JabberStream * js_p = qmsg_p->js_p;
  sqlite3 * db_p = db_open(qmsg_p->uname);
  uint32_t own_id = 0;
  uint8_t key_and_tag[LURCH_OM2_KEY_AND_TAG_LEN];
  char * envelope = (void *) 0;
  int envelope_len = 0;
  uint8_t * payload_p = (void *) 0;
  size_t payload_len = 0;
  xmlnode * encrypted_p = (void *) 0;
  xmlnode * header_p = (void *) 0;
  xmlnode * encryption_p = (void *) 0;
  GHashTable * keys_nodes_p = g_hash_table_new(g_str_hash, g_str_equal);
  gboolean reached_recipient = FALSE;
  int reached = 0;
  char * id_str = (void *) 0;

  if (!db_p || own_device_id_get(qmsg_p->uname, &own_id)) {
    goto cleanup;
  }

  envelope = envelope_create(qmsg_p->uname, qmsg_p->body, &envelope_len);
  if (!envelope || lurch_om2_payload_encrypt((uint8_t *) envelope, envelope_len, key_and_tag, &payload_p, &payload_len)) {
    goto cleanup;
  }

  encrypted_p = xmlnode_new_child(qmsg_p->stanza_p, "encrypted");
  xmlnode_set_namespace(encrypted_p, NS_OM2);
  header_p = xmlnode_new_child(encrypted_p, "header");
  id_str = g_strdup_printf("%u", own_id);
  xmlnode_set_attrib(header_p, "sid", id_str);
  g_free(id_str);

  for (GList * curr_p = qmsg_p->targets_p; curr_p; curr_p = curr_p->next) {
    om2_target * target_p = curr_p->data;

    if (!header_add_key(db_p, header_p, keys_nodes_p, target_p, key_and_tag, sizeof(key_and_tag))) {
      reached++;
      if (!g_strcmp0(target_p->jid, qmsg_p->recipient)) {
        reached_recipient = TRUE;
      }
    }
  }

  if (!reached || (qmsg_p->must_reach_recipient && !reached_recipient)) {
    purple_debug_error(LOG, "%s: could not encrypt for any device of %s\n", __func__, qmsg_p->recipient);
    error_show(js_p, qmsg_p->recipient, MSG_NOT_SENT);
    goto cleanup;
  }

  node_set_b64(xmlnode_new_child(encrypted_p, "payload"), payload_p, payload_len);

  encryption_p = xmlnode_new_child(qmsg_p->stanza_p, "encryption");
  xmlnode_set_namespace(encryption_p, NS_EME);
  xmlnode_set_attrib(encryption_p, "namespace", NS_OM2);
  xmlnode_set_attrib(encryption_p, "name", "OMEMO 2");
  xmlnode_set_namespace(xmlnode_new_child(qmsg_p->stanza_p, "store"), NS_HINTS);

  jabber_send(js_p, qmsg_p->stanza_p);

cleanup:
  lurch_om2_wipe(key_and_tag, sizeof(key_and_tag));
  if (envelope) {
    lurch_om2_wipe(envelope, envelope_len);
    g_free(envelope);
  }
  g_free(payload_p);
  g_hash_table_destroy(keys_nodes_p);
  sqlite3_close(db_p);
  qmsg_free(qmsg_p);
}

/**
 * Starts a session with a device using its bundle.
 *
 * @return 0 on success.
 */
static int session_create_from_bundle(JabberStream * js_p, const char * uname, const om2_target * target_p, xmlnode * bundle_node_p) {
  lurch_om2_bundle bundle;
  lurch_om2_keypair ik;
  uint32_t own_id = 0;
  lurch_om2_session * session_p = (void *) 0;
  sqlite3 * db_p = (void *) 0;
  xmlnode * spk_p = xmlnode_get_child(bundle_node_p, "spk");
  xmlnode * prekeys_p = xmlnode_get_child(bundle_node_p, "prekeys");
  int pk_count = 0;
  int chosen = 0;
  int ret_val = -1;

  memset(&bundle, 0, sizeof(bundle));

  if (!spk_p || !prekeys_p
      || !id_parse(xmlnode_get_attrib(spk_p, "id"), &bundle.spk_id)
      || !node_get_b64_exact(spk_p, bundle.spk, sizeof(bundle.spk))
      || !node_get_b64_exact(xmlnode_get_child(bundle_node_p, "spks"), bundle.spk_sig, sizeof(bundle.spk_sig))
      || !node_get_b64_exact(xmlnode_get_child(bundle_node_p, "ik"), bundle.ik_ed, sizeof(bundle.ik_ed))) {
    purple_debug_warning(LOG, "%s: malformed bundle of %s:%u\n", __func__, target_p->jid, target_p->device_id);
    return -1;
  }

  for (xmlnode * pk_p = xmlnode_get_child(prekeys_p, "pk"); pk_p; pk_p = xmlnode_get_next_twin(pk_p)) {
    pk_count++;
  }
  if (!pk_count) {
    purple_debug_warning(LOG, "%s: bundle of %s:%u has no PreKeys\n", __func__, target_p->jid, target_p->device_id);
    return -1;
  }

  // the XEP asks for a random one, to make it unlikely that two devices use the same one
  chosen = g_random_int_range(0, pk_count);
  for (xmlnode * pk_p = xmlnode_get_child(prekeys_p, "pk"); pk_p; pk_p = xmlnode_get_next_twin(pk_p)) {
    if (!chosen--) {
      if (!id_parse(xmlnode_get_attrib(pk_p, "id"), &bundle.pk_id) || !node_get_b64_exact(pk_p, bundle.pk, sizeof(bundle.pk))) {
        purple_debug_warning(LOG, "%s: malformed PreKey in the bundle of %s:%u\n", __func__, target_p->jid, target_p->device_id);
        return -1;
      }
      break;
    }
  }

  db_p = db_open(uname);
  if (!db_p || own_identity_get(uname, &ik, &own_id)) {
    goto cleanup;
  }

  ret_val = db_identity_check(db_p, target_p->jid, target_p->device_id, bundle.ik_ed);
  if (ret_val != 1) {
    if (ret_val == 0) {
      char * msg = g_strdup_printf(MSG_IDENTITY_CHANGED, target_p->device_id, target_p->jid);
      error_show(js_p, target_p->jid, msg);
      g_free(msg);
    }
    ret_val = -1;
    goto cleanup_ik;
  }

  ret_val = lurch_om2_session_create_active(&ik, &bundle, &session_p);
  if (ret_val) {
    purple_debug_warning(LOG, "%s: failed to start session with %s:%u, the signature might be invalid (%i)\n", __func__, target_p->jid, target_p->device_id, ret_val);
    goto cleanup_ik;
  }

  // the first bundle of a device is what is trusted on first use, as its signature was just verified
  ret_val = db_identity_remember(db_p, target_p->jid, target_p->device_id, bundle.ik_ed);
  if (!ret_val) {
    ret_val = db_session_set(db_p, target_p->jid, target_p->device_id, session_p);
  }

cleanup_ik:
  lurch_om2_wipe(&ik, sizeof(ik));

cleanup:
  lurch_om2_session_destroy(session_p);
  sqlite3_close(db_p);
  return ret_val;
}

static void bundle_response_cb(JabberStream * js_p, const char * from, JabberIqType type, const char * id, xmlnode * packet_p, gpointer data_p) {
  om2_bundle_request * req_p = data_p;
  om2_queued_msg * qmsg_p = req_p->qmsg_p;
  om2_target * target_p = req_p->target_p;
  char * device_id_str = g_strdup_printf("%u", target_p->device_id);
  xmlnode * pubsub_p = xmlnode_get_child_with_namespace(packet_p, "pubsub", NS_PUBSUB);
  xmlnode * items_p = pubsub_p ? xmlnode_get_child(pubsub_p, "items") : (void *) 0;
  xmlnode * bundle_p = (void *) 0;
  (void) from;
  (void) id;

  if (type == JABBER_IQ_RESULT && items_p) {
    // the server might respond with more than what was asked for
    for (xmlnode * item_p = xmlnode_get_child(items_p, "item"); item_p; item_p = xmlnode_get_next_twin(item_p)) {
      if (!g_strcmp0(xmlnode_get_attrib(item_p, "id"), device_id_str)) {
        bundle_p = xmlnode_get_child_with_namespace(item_p, "bundle", NS_OM2);
        break;
      }
    }
  }

  if (!bundle_p) {
    purple_debug_warning(LOG, "%s: could not get the bundle of %s:%u\n", __func__, target_p->jid, target_p->device_id);
  } else {
    sqlite3 * db_p = db_open(qmsg_p->uname);
    lurch_om2_session * existing_p = db_p ? db_session_get(db_p, target_p->jid, target_p->device_id) : (void *) 0;

    // A message sent right before this one could have started it already.
    if (!existing_p) {
      (void) session_create_from_bundle(js_p, qmsg_p->uname, target_p, bundle_p);
    }

    lurch_om2_session_destroy(existing_p);
    sqlite3_close(db_p);
  }

  g_free(device_id_str);
  g_free(req_p);

  if (--qmsg_p->pending == 0) {
    qmsg_finish(qmsg_p);
  }
}

static void bundle_request(om2_queued_msg * qmsg_p, om2_target * target_p) {
  JabberIq * jiq_p = jabber_iq_new(qmsg_p->js_p, JABBER_IQ_GET);
  xmlnode * pubsub_p = xmlnode_new_child(jiq_p->node, "pubsub");
  xmlnode * items_p = xmlnode_new_child(pubsub_p, "items");
  char * id_str = g_strdup_printf("%u", target_p->device_id);
  om2_bundle_request * req_p = g_new0(om2_bundle_request, 1);

  xmlnode_set_attrib(jiq_p->node, "to", target_p->jid);
  xmlnode_set_namespace(pubsub_p, NS_PUBSUB);
  xmlnode_set_attrib(items_p, "node", NODE_BUNDLES);
  xmlnode_set_attrib(xmlnode_new_child(items_p, "item"), "id", id_str);
  g_free(id_str);

  req_p->qmsg_p = qmsg_p;
  req_p->target_p = target_p;

  jabber_iq_set_callback(jiq_p, bundle_response_cb, req_p);
  jabber_iq_send(jiq_p);
}

/**
 * Collects the devices of a JID that exclusively use OMEMO 2.
 *
 * @param skip_id A device to leave out, i.e. this one. 0 for none, as IDs start at 1.
 */
static GList * targets_add(GList * targets_p, sqlite3 * db_p, const char * jid, GList * legacy_ids_p, uint32_t skip_id) {
  GList * ids_p = db_devices_get(db_p, jid);

  for (GList * curr_p = ids_p; curr_p; curr_p = curr_p->next) {
    uint32_t id = GPOINTER_TO_UINT(curr_p->data);

    if (id != skip_id && !list_contains(legacy_ids_p, id)) {
      om2_target * target_p = g_new0(om2_target, 1);

      target_p->jid = g_strdup(jid);
      target_p->device_id = id;
      targets_p = g_list_prepend(targets_p, target_p);
    }
  }

  g_list_free(ids_p);
  return targets_p;
}

void lurch_om2_message_send(JabberStream * js_p, const char * recipient, GList * legacy_ids_p, GList * own_legacy_ids_p, xmlnode ** stanza_pp) {
  char * uname = js_get_uname(js_p);
  sqlite3 * db_p = db_open(uname);
  uint32_t own_id = 0;
  GList * targets_p = (void *) 0;
  gboolean recipient_is_om2_only = FALSE;
  gboolean recipient_has_om2 = FALSE;
  om2_queued_msg * qmsg_p = (void *) 0;
  xmlnode * body_node_p = xmlnode_get_child(*stanza_pp, "body");
  xmlnode * html_node_p = (void *) 0;
  GList * no_session_p = (void *) 0;

  if (!db_p || !body_node_p) {
    goto cleanup;
  }

  if (own_device_id_get(uname, &own_id)) {
    goto cleanup;
  }

  // when writing to the own account, the own devices are the recipient's
  targets_p = targets_add(targets_p, db_p, recipient, legacy_ids_p, g_strcmp0(uname, recipient) ? 0 : own_id);
  recipient_has_om2 = targets_p != (void *) 0;
  recipient_is_om2_only = recipient_has_om2 && !legacy_ids_p;

  if (g_strcmp0(uname, recipient)) {
    targets_p = targets_add(targets_p, db_p, uname, own_legacy_ids_p, own_id);
  }

  if (!targets_p) {
    goto cleanup;
  }

  qmsg_p = g_new0(om2_queued_msg, 1);
  qmsg_p->js_p = js_p;
  qmsg_p->uname = g_strdup(uname);
  qmsg_p->recipient = g_strdup(recipient);
  qmsg_p->body = xmlnode_get_data(body_node_p);
  qmsg_p->targets_p = targets_p;
  qmsg_p->must_reach_recipient = recipient_is_om2_only;
  targets_p = (void *) 0;

  // Everything that is not encrypted must not contain the message any more.
  qmsg_p->stanza_p = xmlnode_copy(*stanza_pp);
  xmlnode_free(xmlnode_get_child(qmsg_p->stanza_p, "body"));
  html_node_p = xmlnode_get_child(qmsg_p->stanza_p, "html");
  if (html_node_p) {
    xmlnode_free(html_node_p);
  }

  if (recipient_is_om2_only) {
    // The caller would send it with the old version, or in plaintext. It is not freed as it belongs to the jabber prpl.
    *stanza_pp = (void *) 0;
  }

  for (GList * curr_p = qmsg_p->targets_p; curr_p; curr_p = curr_p->next) {
    om2_target * target_p = curr_p->data;
    lurch_om2_session * session_p = db_session_get(db_p, target_p->jid, target_p->device_id);

    if (session_p) {
      lurch_om2_session_destroy(session_p);
    } else {
      no_session_p = g_list_prepend(no_session_p, target_p);
    }
  }

  if (!no_session_p) {
    qmsg_finish(qmsg_p);
    goto cleanup;
  }

  // first count them all, as the responses could be handled at any point after sending the first request
  qmsg_p->pending = (int) g_list_length(no_session_p);
  for (GList * curr_p = no_session_p; curr_p; curr_p = curr_p->next) {
    bundle_request(qmsg_p, curr_p->data);
  }
  g_list_free(no_session_p);

cleanup:
  g_list_free_full(targets_p, target_free);
  sqlite3_close(db_p);
  g_free(uname);
}

/** Sends an empty message, which is just for managing the session. */
static void empty_message_send(JabberStream * js_p, sqlite3 * db_p, const char * jid, uint32_t device_id, uint32_t own_id) {
  static const uint8_t zeros[LURCH_OM2_EMPTY_LEN] = {0};
  xmlnode * message_p = xmlnode_new("message");
  xmlnode * encrypted_p = xmlnode_new_child(message_p, "encrypted");
  xmlnode * header_p = xmlnode_new_child(encrypted_p, "header");
  GHashTable * keys_nodes_p = g_hash_table_new(g_str_hash, g_str_equal);
  om2_target target = { .jid = (char *) jid, .device_id = device_id };
  char * id_str = g_strdup_printf("%u", own_id);

  xmlnode_set_attrib(message_p, "to", jid);
  xmlnode_set_attrib(message_p, "type", "chat");
  xmlnode_set_namespace(encrypted_p, NS_OM2);
  xmlnode_set_attrib(header_p, "sid", id_str);
  g_free(id_str);

  if (!header_add_key(db_p, header_p, keys_nodes_p, &target, zeros, sizeof(zeros))) {
    xmlnode_set_namespace(xmlnode_new_child(message_p, "store"), NS_HINTS);
    jabber_send(js_p, message_p);
  }

  g_hash_table_destroy(keys_nodes_p);
  xmlnode_free(message_p);
}

/*
 * Receiving
 */

/**
 * Applies a decrypted envelope to the stanza. Only the body is used: what comes from the envelope is authentic, but the
 * rest of the code is not prepared for anything else coming from it.
 *
 * @return 0 on success.
 */
static int envelope_apply(JabberStream * js_p, const char * uname, const char * sender, const char * recipient, const uint8_t * plain_p, size_t plain_len, xmlnode ** stanza_pp) {
  xmlnode * envelope_p = xmlnode_from_str((const char *) plain_p, (gssize) plain_len);
  xmlnode * content_p = (void *) 0;
  xmlnode * from_p = (void *) 0;
  xmlnode * to_p = (void *) 0;
  xmlnode * body_p = (void *) 0;
  xmlnode * encrypted_p = (void *) 0;
  int ret_val = -1;

  if (!envelope_p || g_strcmp0(envelope_p->name, "envelope") || g_strcmp0(xmlnode_get_namespace(envelope_p), NS_SCE)) {
    purple_debug_warning(LOG, "%s: not an SCE envelope\n", __func__);
    goto cleanup;
  }

  // These prevent the server from changing who a message was sent by or to.
  from_p = xmlnode_get_child(envelope_p, "from");
  if (from_p) {
    char * from_bare = jabber_get_bare_jid(xmlnode_get_attrib(from_p, "jid"));
    gboolean matches = from_bare && !g_strcmp0(from_bare, sender);

    g_free(from_bare);
    if (!matches) {
      purple_debug_warning(LOG, "%s: the envelope is from somebody else than %s\n", __func__, sender);
      goto cleanup;
    }
  }

  to_p = xmlnode_get_child(envelope_p, "to");
  if (to_p) {
    char * to_bare = jabber_get_bare_jid(xmlnode_get_attrib(to_p, "jid"));
    gboolean matches = to_bare && (!g_strcmp0(to_bare, uname) || !g_strcmp0(to_bare, recipient));

    g_free(to_bare);
    if (!matches) {
      purple_debug_warning(LOG, "%s: the envelope is for somebody else\n", __func__);
      goto cleanup;
    }
  }

  ret_val = 0;

  content_p = xmlnode_get_child(envelope_p, "content");
  if (content_p && xmlnode_get_child_with_namespace(content_p, "opt-out", NS_OM2)) {
    error_show(js_p, sender, "This contact asked to not use OMEMO any more. Use '/lurch blacklist add' if you agree to continue without encryption.");
  }

  body_p = content_p ? xmlnode_get_child(content_p, "body") : (void *) 0;

  encrypted_p = xmlnode_get_child_with_namespace(*stanza_pp, "encrypted", NS_OM2);
  if (encrypted_p) {
    xmlnode_free(encrypted_p);
  }

  // A body outside of the encrypted part could be from anybody, e.g. the fallback text, or something else put there.
  while (xmlnode_get_child(*stanza_pp, "body")) {
    xmlnode_free(xmlnode_get_child(*stanza_pp, "body"));
  }

  if (body_p) {
    char * body = xmlnode_get_data(body_p);

    if (!g_strcmp0(sender, uname) && g_strcmp0(recipient, uname)) {
      // libpurple doesn't know what to do with messages from the own account to somebody else
      PurpleAccount * acc_p = purple_connection_get_account(js_p->gc);
      PurpleConversation * conv_p = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, recipient, acc_p);

      if (!conv_p) {
        conv_p = purple_conversation_new(PURPLE_CONV_TYPE_IM, acc_p, recipient);
      }
      if (body) {
        purple_conversation_write(conv_p, uname, body, PURPLE_MESSAGE_SEND, time((void *) 0));
      }
      xmlnode_free(*stanza_pp);
      *stanza_pp = (void *) 0;
    } else if (body) {
      xmlnode * new_body_p = xmlnode_new_child(*stanza_pp, "body");

      xmlnode_set_namespace(new_body_p, NS_CLIENT);
      xmlnode_insert_data(new_body_p, body, -1);
    }

    if (body) {
      lurch_om2_wipe(body, strlen(body));
    }
    g_free(body);
  }

cleanup:
  xmlnode_free(envelope_p);
  return ret_val;
}

/** Removes a used PreKey and publishes the bundle again, as the XEP asks for. */
static void pk_consume(JabberStream * js_p, sqlite3 * db_p, const lurch_om2_keypair * ik_p, uint32_t own_id, uint32_t pk_id) {
  sqlite3_stmt * stmt_p = db_prepare(db_p, "DELETE FROM pk WHERE id = ?1;");

  if (stmt_p) {
    sqlite3_bind_int64(stmt_p, 1, pk_id);
    sqlite3_step(stmt_p);
    sqlite3_finalize(stmt_p);
  }

  if (pk_replenish(db_p)) {
    purple_debug_error(LOG, "%s: failed to generate new PreKeys\n", __func__);
  }

  bundle_publish(js_p, db_p, ik_p, own_id);
}

static gboolean db_keypair_get(sqlite3 * db_p, const char * sql, uint32_t id, lurch_om2_keypair * kp_p) {
  gboolean found = FALSE;
  sqlite3_stmt * stmt_p = db_prepare(db_p, sql);

  if (stmt_p) {
    sqlite3_bind_int64(stmt_p, 1, id);
    if (sqlite3_step(stmt_p) == SQLITE_ROW) {
      found = db_blob_get(stmt_p, 0, kp_p->priv, sizeof(kp_p->priv)) && db_blob_get(stmt_p, 1, kp_p->pub, sizeof(kp_p->pub));
    }
  }

  sqlite3_finalize(stmt_p);
  return found;
}

int lurch_om2_message_receive(JabberStream * js_p, xmlnode ** stanza_pp) {
  xmlnode * stanza_p = *stanza_pp;
  xmlnode * encrypted_p = xmlnode_get_child_with_namespace(stanza_p, "encrypted", NS_OM2);
  xmlnode * header_p = encrypted_p ? xmlnode_get_child(encrypted_p, "header") : (void *) 0;
  xmlnode * payload_p = encrypted_p ? xmlnode_get_child(encrypted_p, "payload") : (void *) 0;
  xmlnode * own_key_p = (void *) 0;
  const char * type = xmlnode_get_attrib(stanza_p, "type");
  const char * from = xmlnode_get_attrib(stanza_p, "from");
  const char * to = xmlnode_get_attrib(stanza_p, "to");
  char * uname = js_get_uname(js_p);
  char * sender = (void *) 0;
  char * recipient = (void *) 0;
  sqlite3 * db_p = (void *) 0;
  lurch_om2_keypair ik;
  gboolean have_ik = FALSE;
  uint32_t own_id = 0;
  uint32_t sid = 0;
  uint8_t * key_data_p = (void *) 0;
  gsize key_data_len = 0;
  uint8_t * payload_data_p = (void *) 0;
  gsize payload_data_len = 0;
  uint8_t * plain_key_p = (void *) 0;
  size_t plain_key_len = 0;
  uint8_t * plain_p = (void *) 0;
  size_t plain_len = 0;
  lurch_om2_session * session_p = (void *) 0;
  const uint8_t * msg_p = (void *) 0;
  size_t msg_len = 0;
  gboolean is_new_session = FALSE;
  gboolean send_empty = FALSE;
  gboolean failed = FALSE;
  lurch_om2_key_exchange kex;
  int needs_heartbeat = 0;
  int handled = 1;
  int ret_val = 0;

  memset(&kex, 0, sizeof(kex));

  // Errors just bounce an own message, and the others are not for chatting.
  if (type && g_strcmp0(type, "chat") && g_strcmp0(type, "normal")) {
    if (!g_strcmp0(type, "groupchat")) {
      purple_debug_warning(LOG, "%s: OMEMO 2 is not supported in group chats yet\n", __func__);
      // it might contain the old version as well
      handled = 0;
    }
    goto cleanup;
  }

  // without a sender, the message comes from the own account
  sender = from ? jabber_get_bare_jid(from) : g_strdup(uname);
  recipient = to ? jabber_get_bare_jid(to) : g_strdup(uname);
  if (!sender || !recipient || !header_p || !id_parse(xmlnode_get_attrib(header_p, "sid"), &sid)) {
    purple_debug_warning(LOG, "%s: ignoring malformed message\n", __func__);
    goto cleanup;
  }

  db_p = db_open(uname);
  if (!db_p || own_identity_get(uname, &ik, &own_id)) {
    goto cleanup;
  }
  have_ik = TRUE;

  if (!g_strcmp0(sender, uname) && sid == own_id) {
    // an own message coming back, which cannot contain a key for this device
    goto cleanup;
  }

  for (xmlnode * keys_p = xmlnode_get_child(header_p, "keys"); keys_p && !own_key_p; keys_p = xmlnode_get_next_twin(keys_p)) {
    char * keys_jid = jabber_get_bare_jid(xmlnode_get_attrib(keys_p, "jid"));
    gboolean is_own = keys_jid && !g_strcmp0(keys_jid, uname);

    g_free(keys_jid);
    if (!is_own) {
      continue;
    }

    for (xmlnode * key_p = xmlnode_get_child(keys_p, "key"); key_p; key_p = xmlnode_get_next_twin(key_p)) {
      uint32_t rid = 0;

      if (id_parse(xmlnode_get_attrib(key_p, "rid"), &rid) && rid == own_id) {
        own_key_p = key_p;
        break;
      }
    }
  }

  if (!own_key_p) {
    // A message can contain the old version as well, which is then up to the caller.
    handled = xmlnode_get_child_with_namespace(stanza_p, "encrypted", NS_LEGACY) ? 0 : 1;
    if (handled) {
      purple_debug_info(LOG, "%s: no key for this device in the message from %s:%u\n", __func__, sender, sid);
      if (payload_p) {
        error_show(js_p, sender, MSG_NO_KEY);
      }
    }
    goto cleanup;
  }

  key_data_p = node_get_b64(own_key_p, &key_data_len);
  if (!key_data_p || !key_data_len) {
    failed = TRUE;
    purple_debug_warning(LOG, "%s: empty key from %s:%u\n", __func__, sender, sid);
    goto cleanup;
  }

  session_p = db_session_get(db_p, sender, sid);

  const char * kex_attr = xmlnode_get_attrib(own_key_p, "kex");
  if (!g_strcmp0(kex_attr, "true") || !g_strcmp0(kex_attr, "1")) {
    if (lurch_om2_key_exchange_parse(key_data_p, key_data_len, &kex)) {
      failed = TRUE;
      purple_debug_warning(LOG, "%s: malformed key exchange from %s:%u\n", __func__, sender, sid);
      goto cleanup;
    }

    msg_p = kex.msg_p;
    msg_len = kex.msg_len;

    if (!session_p || !lurch_om2_session_has_remote_ek(session_p, kex.ek)) {
      lurch_om2_keypair spk;
      lurch_om2_keypair pk;
      lurch_om2_session * new_session_p = (void *) 0;

      ret_val = db_identity_check(db_p, sender, sid, kex.ik_ed);
      if (ret_val != 1) {
        if (ret_val == 0) {
          char * msg = g_strdup_printf(MSG_IDENTITY_CHANGED, sid, sender);
          error_show(js_p, sender, msg);
          g_free(msg);
        } else {
          failed = TRUE;
        }
        goto cleanup;
      }

      if (!db_keypair_get(db_p, "SELECT priv, pub FROM spk WHERE id = ?1;", kex.spk_id, &spk)
          || !db_keypair_get(db_p, "SELECT priv, pub FROM pk WHERE id = ?1;", kex.pk_id, &pk)) {
        // Every key exchange must use a PreKey. It might be used already, or just not exist.
        purple_debug_warning(LOG, "%s: key exchange from %s:%u with an unknown key\n", __func__, sender, sid);
        failed = TRUE;
        goto cleanup;
      }

      ret_val = lurch_om2_session_create_passive(&ik, &spk, &pk, &kex, &new_session_p);
      lurch_om2_wipe(&spk, sizeof(spk));
      lurch_om2_wipe(&pk, sizeof(pk));
      if (ret_val) {
        purple_debug_warning(LOG, "%s: failed to start a session with %s:%u\n", __func__, sender, sid);
        failed = TRUE;
        goto cleanup;
      }

      // nothing about the old session changes in case this message turns out to not be authentic
      lurch_om2_session_destroy(session_p);
      session_p = new_session_p;
      is_new_session = TRUE;
    }
  } else {
    msg_p = key_data_p;
    msg_len = key_data_len;

    if (!session_p) {
      purple_debug_warning(LOG, "%s: message from %s:%u without a session\n", __func__, sender, sid);
      failed = TRUE;
      goto cleanup;
    }

    // the session is known to have the IK from when it was created
    if (db_identity_check(db_p, sender, sid, lurch_om2_session_get_remote_ik(session_p)) != 1) {
      char * msg = g_strdup_printf(MSG_IDENTITY_CHANGED, sid, sender);
      error_show(js_p, sender, msg);
      g_free(msg);
      goto cleanup;
    }
  }

  ret_val = lurch_om2_session_decrypt(session_p, msg_p, msg_len, &plain_key_p, &plain_key_len, &needs_heartbeat);
  if (ret_val == LURCH_OM2_ERR_DUPLICATE) {
    // must not be reported, and whatever else is in there must not be shown again either
    purple_debug_info(LOG, "%s: ignoring a duplicate message from %s:%u\n", __func__, sender, sid);
    xmlnode_free(*stanza_pp);
    *stanza_pp = (void *) 0;
    goto cleanup;
  } else if (ret_val) {
    purple_debug_warning(LOG, "%s: failed to decrypt the message from %s:%u (%i)\n", __func__, sender, sid, ret_val);
    failed = TRUE;
    goto cleanup;
  }

  // The message is authentic from here on.
  if (db_identity_remember(db_p, sender, sid, lurch_om2_session_get_remote_ik(session_p))
      || db_session_set(db_p, sender, sid, session_p)) {
    purple_debug_error(LOG, "%s: failed to save the session with %s:%u\n", __func__, sender, sid);
    failed = TRUE;
    goto cleanup;
  }

  if (is_new_session) {
    pk_consume(js_p, db_p, &ik, own_id, kex.pk_id);
    send_empty = TRUE;
  }
  if (needs_heartbeat) {
    send_empty = TRUE;
  }

  if (payload_p) {
    if (plain_key_len != LURCH_OM2_KEY_AND_TAG_LEN) {
      purple_debug_warning(LOG, "%s: key from %s:%u has an invalid length: %zu\n", __func__, sender, sid, plain_key_len);
      failed = TRUE;
      goto cleanup;
    }

    payload_data_p = node_get_b64(payload_p, &payload_data_len);
    if (!payload_data_p || !payload_data_len
        || lurch_om2_payload_decrypt(plain_key_p, payload_data_p, payload_data_len, &plain_p, &plain_len)) {
      purple_debug_warning(LOG, "%s: failed to decrypt the payload from %s:%u\n", __func__, sender, sid);
      failed = TRUE;
      goto cleanup;
    }

    if (envelope_apply(js_p, uname, sender, recipient, plain_p, plain_len, stanza_pp)) {
      failed = TRUE;
      goto cleanup;
    }
  } else {
    // An empty message, nothing to show. A body next to it would not be authentic.
    purple_debug_info(LOG, "%s: received an empty message from %s:%u\n", __func__, sender, sid);
    xmlnode_free(*stanza_pp);
    *stanza_pp = (void *) 0;
  }

cleanup:
  if (send_empty && db_p) {
    empty_message_send(js_p, db_p, sender, sid, own_id);
  }

  if (failed) {
    error_show(js_p, sender, MSG_DECRYPT_FAILED);
    // It is unknown whether this device is on the list then, in which case the XEP asks for an up-to-date one.
    lurch_om2_devicelist_request(js_p, sender);
  }

  if (failed && *stanza_pp) {
    // Nothing of it can be shown. In particular not the fallback, which would look like an actual message.
    xmlnode_free(*stanza_pp);
    *stanza_pp = (void *) 0;
  }

  if (have_ik) {
    lurch_om2_wipe(&ik, sizeof(ik));
  }
  if (plain_key_p) {
    lurch_om2_wipe(plain_key_p, plain_key_len);
    g_free(plain_key_p);
  }
  if (plain_p) {
    lurch_om2_wipe(plain_p, plain_len);
    g_free(plain_p);
  }
  g_free(key_data_p);
  g_free(payload_data_p);
  lurch_om2_session_destroy(session_p);
  sqlite3_close(db_p);
  g_free(sender);
  g_free(recipient);
  g_free(uname);

  return handled;
}

/*
 * Commands
 */

static void cmd_print(PurpleConversation * conv_p, const char * msg) {
  purple_conversation_write(conv_p, "lurch", msg, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time((void *) 0));
}

/** The form of a fingerprint recommended by the XEP: the Curve25519 key in 8 groups of 8. */
static char * fp_format(const uint8_t * ik_ed_p) {
  uint8_t curve[LURCH_OM2_KEY_LEN];
  GString * fp_p = g_string_new((void *) 0);

  if (lurch_om2_ed_to_curve(ik_ed_p, curve)) {
    g_string_append(fp_p, "(invalid key)");
    return g_string_free(fp_p, FALSE);
  }

  for (int i = 0; i < LURCH_OM2_KEY_LEN; i++) {
    g_string_append_printf(fp_p, "%02x%s", curve[i], (i % 4 == 3 && i != LURCH_OM2_KEY_LEN - 1) ? " " : "");
  }

  return g_string_free(fp_p, FALSE);
}

static void cmd_status(PurpleConversation * conv_p, sqlite3 * db_p, const char * jid) {
  GString * msg_p = g_string_new((void *) 0);
  GList * ids_p = db_devices_get(db_p, jid);

  g_string_append_printf(msg_p, "OMEMO 2 devices of %s:\n", jid);
  if (!ids_p) {
    g_string_append(msg_p, "(none known)\n");
  }

  for (GList * curr_p = ids_p; curr_p; curr_p = curr_p->next) {
    uint32_t id = GPOINTER_TO_UINT(curr_p->data);
    uint8_t ik[LURCH_OM2_KEY_LEN];
    gboolean known = FALSE;
    sqlite3_stmt * stmt_p = db_prepare(db_p, "SELECT ik FROM identity WHERE jid = ?1 AND device = ?2;");

    if (stmt_p) {
      sqlite3_bind_text(stmt_p, 1, jid, -1, SQLITE_STATIC);
      sqlite3_bind_int64(stmt_p, 2, id);
      known = sqlite3_step(stmt_p) == SQLITE_ROW && db_blob_get(stmt_p, 0, ik, sizeof(ik));
      sqlite3_finalize(stmt_p);
    }

    if (known) {
      char * fp = fp_format(ik);
      g_string_append_printf(msg_p, "%u: %s\n", id, fp);
      g_free(fp);
    } else {
      g_string_append_printf(msg_p, "%u: (no session yet)\n", id);
    }
  }

  cmd_print(conv_p, msg_p->str);
  g_list_free(ids_p);
  g_string_free(msg_p, TRUE);
}

void lurch_om2_cmd(PurpleConversation * conv_p, const char * arg) {
  PurpleAccount * acc_p = purple_conversation_get_account(conv_p);
  char * uname = lurch_util_uname_strip(purple_account_get_username(acc_p));
  char * bare_jid = jabber_get_bare_jid(purple_conversation_get_name(conv_p));
  sqlite3 * db_p = db_open(uname);
  lurch_om2_keypair ik;
  uint32_t own_id = 0;

  if (!db_p || !bare_jid) {
    cmd_print(conv_p, "Failed to access the OMEMO 2 data, see the debug log for details.");
    goto cleanup;
  }

  if (!g_strcmp0(arg, "show")) {
    uint8_t ik_ed[LURCH_OM2_KEY_LEN];

    if (own_identity_get(uname, &ik, &own_id) || lurch_om2_curve_to_ed(ik.pub, ik_ed)) {
      cmd_print(conv_p, "Failed to load the own key, see the debug log for details.");
    } else {
      char * fp = fp_format(ik_ed);
      char * msg = g_strdup_printf("This device: %u\nFingerprint: %s", own_id, fp);
      cmd_print(conv_p, msg);
      g_free(msg);
      g_free(fp);
      lurch_om2_wipe(&ik, sizeof(ik));
    }
  } else if (!g_strcmp0(arg, "reset")) {
    static const char * const sql[] = { "DELETE FROM session WHERE jid = ?1;", "DELETE FROM identity WHERE jid = ?1;" };

    for (size_t i = 0; i < G_N_ELEMENTS(sql); i++) {
      sqlite3_stmt * stmt_p = db_prepare(db_p, sql[i]);
      if (stmt_p) {
        sqlite3_bind_text(stmt_p, 1, bare_jid, -1, SQLITE_STATIC);
        sqlite3_step(stmt_p);
        sqlite3_finalize(stmt_p);
      }
    }
    cmd_print(conv_p, "Removed the OMEMO 2 sessions and known keys of this contact. New ones are built and trusted with the next message, so verify the fingerprints afterwards.");
  } else if (!arg || !g_strcmp0(arg, "status")) {
    cmd_status(conv_p, db_p, bare_jid);
  } else {
    cmd_print(conv_p, "Valid arguments for 'omemo2' are 'status', 'show', and 'reset'.");
  }

cleanup:
  sqlite3_close(db_p);
  g_free(bare_jid);
  g_free(uname);
}
