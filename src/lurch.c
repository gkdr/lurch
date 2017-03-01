#define PURPLE_PLUGINS

#include <glib.h>

#include <inttypes.h>
#include <string.h>
#include <time.h>

#include "account.h"
#include "cmds.h"
#include "conversation.h"
#include "debug.h"
#include "notify.h"
#include "plugin.h"
#include "util.h"
#include "version.h"
#include "xmlnode.h"

#include "jabber.h"
#include "jutil.h"
#include "pep.h"

#include "libomemo.h"
#include "libomemo_crypto.h"
#include "libomemo_storage.h"

#include "axc.h"
#include "axc_store.h"

#ifdef _WIN32
#define strnlen(a, b) (MIN(strlen(a), (b)))
#endif

#define JABBER_PROTOCOL_ID "prpl-jabber"

// see https://www.ietf.org/rfc/rfc3920.txt
#define JABBER_MAX_LEN_NODE 1023
#define JABBER_MAX_LEN_DOMAIN 1023
#define JABBER_MAX_LEN_BARE JABBER_MAX_LEN_NODE + JABBER_MAX_LEN_DOMAIN + 1

#define LURCH_ACC_SETTING_INITIALIZED "lurch_initialised"

#define LURCH_DB_SUFFIX "_db.sqlite"
#define LURCH_DB_NAME_OMEMO "omemo"
#define LURCH_DB_NAME_AXC "axc"

#define LURCH_ERR           -1000000
#define LURCH_ERR_NOMEM     -1000001
#define LURCH_ERR_NO_BUNDLE -1000010

#define LURCH_ERR_STRING_ENCRYPT "There was an error encrypting the message and it was not sent. " \
                                 "You can try again, or try to find the problem by looking at the debug log."
#define LURCH_ERR_STRING_DECRYPT "There was an error decrypting an OMEMO message addressed to this device. " \
                                 "See the debug log for details."
typedef struct lurch_addr {
  char * jid;
  uint32_t device_id;
} lurch_addr;

typedef struct lurch_queued_msg {
  omemo_message * om_msg_p;
  GList * recipient_addr_l_p;
  GList * no_sess_l_p;
  GHashTable * sess_handled_p;
} lurch_queued_msg;

omemo_crypto_provider crypto = {
    .random_bytes_func = omemo_default_crypto_random_bytes,
    .aes_gcm_encrypt_func = omemo_default_crypto_aes_gcm_encrypt,
    .aes_gcm_decrypt_func = omemo_default_crypto_aes_gcm_decrypt
};

int topic_changed = 0;
int uninstall = 0;

PurpleCmdId lurch_cmd_id = 0;

// key: char * (name of muc), value: GHashTable * (mapping of user alias to full jid)
GHashTable * chat_users_ht_p = (void *) 0;

static void lurch_addr_list_destroy_func(gpointer data) {
  lurch_addr * addr_p = (lurch_addr *) data;
  free(addr_p->jid);
  free(addr_p);
}

/**
 * Creates a queued msg.
 * Note that it just saves the pointers, so make sure they are not freed during
 * the lifetime of this struct and instead use the destroy function when done.
 *
 * @param om_msg_p Pointer to the omemo_message.
 * @param recipient_addr_l_p Pointer to the list of recipient addresses.
 * @param no_sess_l_p Pointer to the list that contains the addresses that do
 *                    not have sessions, i.e. for which bundles were requested.
 * @param cmsg_pp Will point to the pointer of the created queued msg struct.
 * @return 0 on success, negative on error.
 */
static int lurch_queued_msg_create(omemo_message * om_msg_p,
                                   GList * recipient_addr_l_p,
                                   GList * no_sess_l_p,
                                   lurch_queued_msg ** qmsg_pp) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  lurch_queued_msg * qmsg_p = (void *) 0;
  GHashTable * sess_handled_p = (void *) 0;

  qmsg_p = malloc(sizeof(lurch_queued_msg));
  if (!qmsg_p) {
    ret_val = LURCH_ERR_NOMEM;
    err_msg_dbg = g_strdup_printf("failed to malloc space for queued msg struct");
    goto cleanup;
  }

  sess_handled_p = g_hash_table_new(g_str_hash, g_str_equal);

  qmsg_p->om_msg_p = om_msg_p;
  qmsg_p->recipient_addr_l_p = recipient_addr_l_p;
  qmsg_p->no_sess_l_p = no_sess_l_p;
  qmsg_p->sess_handled_p = sess_handled_p;

  *qmsg_pp = qmsg_p;

cleanup:
  if (ret_val) {
    free(qmsg_p);
  }
  if (err_msg_dbg) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  return ret_val;
}

static int lurch_queued_msg_is_handled(const lurch_queued_msg * qmsg_p) {
  return (g_list_length(qmsg_p->no_sess_l_p) == g_hash_table_size(qmsg_p->sess_handled_p)) ? 1 : 0;
}

/**
 * Frees all the memory used by the queued msg.
 */
static void lurch_queued_msg_destroy(lurch_queued_msg * qmsg_p) {
  if (qmsg_p) {
    omemo_message_destroy(qmsg_p->om_msg_p);
    g_list_free_full(qmsg_p->recipient_addr_l_p, free);
    g_hash_table_destroy(qmsg_p->sess_handled_p);
    free(qmsg_p);
  }
}

static char * lurch_queue_make_key_string_s(const char * name, const char * device_id) {
  return g_strconcat(name, "/", device_id, NULL);
}

/**
 * Returns the db name, has to be g_free()d.
 *
 * @param uname The username.
 * @param which Either LURCH_DB_NAME_OMEMO or LURCH_DB_NAME_AXC
 * @return The path string.
 */
static char * lurch_uname_get_db_fn(const char * uname, char * which) {
  return g_strconcat(purple_user_dir(), "/", uname, "_", which, LURCH_DB_SUFFIX, NULL);
}

/**
 * For some reason pidgin returns account names with a trailing "/".
 * This function removes it.
 * All other functions asking for the username assume the "/" is already stripped.
 *
 * @param uname The username.
 * @return A duplicated string with the trailing "/" removed. free() when done.
 */
static char * lurch_uname_strip(const char * uname) {
  char ** split;
  char * stripped;

  split = g_strsplit(uname, "/", 2);
  stripped = g_strdup(split[0]);

  g_strfreev(split);

  return stripped;
}

/**
 * Creates and initializes the axc context.
 *
 * @param uname The username.
 * @param ctx_pp Will point to an initialized axc context on success.
 * @return 0 on success, negative on error.
 */
static int lurch_axc_get_init_ctx(char * uname, axc_context ** ctx_pp) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  axc_context * ctx_p = (void *) 0;
  char * db_fn = (void *) 0;

  ret_val = axc_context_create(&ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to create axc context");
    goto cleanup;
  }

  db_fn = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_AXC);
  ret_val = axc_context_set_db_fn(ctx_p, db_fn, strlen(db_fn));
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to set axc db filename");
    goto cleanup;
  }

  ret_val = axc_init(ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to init axc context");
    goto cleanup;
  }

  *ctx_pp = ctx_p;

cleanup:
  if (ret_val) {
    axc_context_destroy_all(ctx_p);
  }
  if (err_msg_dbg) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }

  free (db_fn);
  return ret_val;
}

/**
 * Does the first-time install of the axc DB.
 * As specified in OMEMO, it checks if the generated device ID already exists.
 * Therefore, it should be called at a point in time when other entries exist.
 *
 * @param uname The username.
 * @return 0 on success, negative on error.
 */
static int lurch_axc_prepare(char * uname) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  axc_context * axc_ctx_p = (void *) 0;
  uint32_t device_id = 0;
  char * db_fn_omemo = (void *) 0;

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get init axc ctx");
    goto cleanup;
  }

  ret_val = axc_get_device_id(axc_ctx_p, &device_id);
  if (!ret_val) {
    // already installed
    goto cleanup;
  }

  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  while (1) {
    ret_val = axc_install(axc_ctx_p);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to install axc");
      goto cleanup;
    }

    ret_val = axc_get_device_id(axc_ctx_p, &device_id);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to get own device id");
      goto cleanup;
    }

    ret_val = omemo_storage_global_device_id_exists(device_id, db_fn_omemo);
    if (ret_val == 1)  {
      ret_val = axc_db_init_status_set(AXC_DB_NEEDS_ROLLBACK, axc_ctx_p);
      if (ret_val) {
        err_msg_dbg = g_strdup_printf("failed to set axc db to rollback");
        goto cleanup;
      }
    } else if (ret_val < 0) {
      err_msg_dbg = g_strdup_printf("failed to access the db %s", db_fn_omemo);
      goto cleanup;
    } else {
      break;
    }
  }

cleanup:
  if (err_msg_dbg) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  axc_context_destroy_all(axc_ctx_p);
  free(db_fn_omemo);

  return ret_val;
}

/**
 * Encrypts a data buffer, usually the omemo symmetric key, using axolotl.
 * Assumes a valid session already exists.
 *
 * @param recipient_addr_p Pointer to the lurch_addr of the recipient.
 * @param key_p Pointer to the key data.
 * @param key_len Length of the key data.
 * @param axc_ctx_p Pointer to the axc_context to use.
 * @param key_ct_pp Will point to a pointer to an axc_buf containing the key ciphertext on success.
 * @return 0 on success, negative on error
 */
static int lurch_key_encrypt(const lurch_addr * recipient_addr_p,
                             const uint8_t * key_p,
                             size_t key_len,
                             axc_context * axc_ctx_p,
                             axc_buf ** key_ct_buf_pp) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  axc_buf * key_buf_p = (void *) 0;
  axc_buf * key_ct_buf_p = (void *) 0;
  axc_address axc_addr = {0};

  purple_debug_info("lurch", "%s: encrypting key for %s:%i\n", __func__, recipient_addr_p->jid, recipient_addr_p->device_id);

  key_buf_p = axc_buf_create(key_p, key_len);
  if (!key_buf_p) {
    err_msg_dbg = g_strdup_printf("failed to create buffer for the key");
    goto cleanup;
  }

  axc_addr.name = recipient_addr_p->jid;
  axc_addr.name_len = strnlen(axc_addr.name, JABBER_MAX_LEN_BARE);
  axc_addr.device_id = recipient_addr_p->device_id;

  ret_val = axc_message_encrypt_and_serialize(key_buf_p, &axc_addr, axc_ctx_p, &key_ct_buf_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to encrypt the key");
    goto cleanup;
  }

  *key_ct_buf_pp = key_ct_buf_p;

cleanup:
  if (ret_val) {
    axc_buf_free(key_ct_buf_p);
  }
  if (err_msg_dbg) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  axc_buf_free(key_buf_p);

  return ret_val;
}

/**
 * For each of the recipients, encrypts the symmetric key using the existing axc session,
 * then adds it to the omemo message.
 * If the session does not exist, the recipient is skipped.
 *
 * @param om_msg_p Pointer to the omemo message.
 * @param addr_l_p Pointer to the head of a list of the intended recipients' lurch_addrs.
 * @param axc_ctx_p Pointer to the axc_context to use.
 * @return 0 on success, negative on error.
 */
static int lurch_msg_encrypt_for_addrs(omemo_message * om_msg_p, GList * addr_l_p, axc_context * axc_ctx_p) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  GList * curr_l_p = (void *) 0;
  lurch_addr * curr_addr_p = (void *) 0;
  axc_address addr = {0};
  axc_buf * curr_key_ct_buf_p = (void *) 0;

  purple_debug_info("lurch", "%s: trying to encrypt key for %i devices\n", __func__, g_list_length(addr_l_p));

  for (curr_l_p = addr_l_p; curr_l_p; curr_l_p = curr_l_p->next) {
    curr_addr_p = (lurch_addr *) curr_l_p->data;
    addr.name = curr_addr_p->jid;
    addr.name_len = strnlen(addr.name, JABBER_MAX_LEN_BARE);
    addr.device_id = curr_addr_p->device_id;

    ret_val = axc_session_exists_initiated(&addr, axc_ctx_p);
    if (ret_val < 0) {
      err_msg_dbg = g_strdup_printf("failed to check if session exists, aborting");
      goto cleanup;
    } else if (!ret_val) {
      continue;
    } else {
      ret_val = lurch_key_encrypt(curr_addr_p,
                                  omemo_message_get_key(om_msg_p),
                                  omemo_message_get_key_len(om_msg_p),
                                  axc_ctx_p,
                                  &curr_key_ct_buf_p);
      if (ret_val) {
        err_msg_dbg = g_strdup_printf("failed to encrypt key for %s:%i", curr_addr_p->jid, curr_addr_p->device_id);
        goto cleanup;
      }

      ret_val = omemo_message_add_recipient(om_msg_p,
                                            curr_addr_p->device_id,
                                            axc_buf_get_data(curr_key_ct_buf_p),
                                            axc_buf_get_len(curr_key_ct_buf_p));
      if (ret_val) {
        err_msg_dbg = g_strdup_printf("failed to add recipient to omemo msg");
        goto cleanup;
      }

      axc_buf_free(curr_key_ct_buf_p);
      curr_key_ct_buf_p = (void *) 0;
    }
  }

cleanup:
  if (err_msg_dbg) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  axc_buf_free(curr_key_ct_buf_p);

  return ret_val;
}

/**
 * Collects the information needed for a bundle and publishes it.
 *
 * @param uname The username.
 * @param js_p Pointer to the connection to use for publishing.
 */
static int lurch_bundle_publish_own(JabberStream * js_p) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  char * uname = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  axc_bundle * axcbundle_p = (void *) 0;
  omemo_bundle * omemobundle_p = (void *) 0;
  axc_buf * curr_buf_p = (void *) 0;
  axc_buf_list_item * next_p = (void *) 0;
  char * bundle_xml = (void *) 0;
  xmlnode * publish_node_bundle_p = (void *) 0;

  uname = lurch_uname_strip(purple_account_get_username(purple_connection_get_account(js_p->gc)));

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to init axc ctx");
    goto cleanup;
  }

  ret_val = axc_bundle_collect(AXC_PRE_KEYS_AMOUNT, axc_ctx_p, &axcbundle_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to collect axc bundle");
    goto cleanup;
  }

  ret_val = omemo_bundle_create(&omemobundle_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to create omemo_bundle");
    goto cleanup;
  }

  ret_val = omemo_bundle_set_device_id(omemobundle_p, axc_bundle_get_reg_id(axcbundle_p));
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to set device id in omemo bundle");
    goto cleanup;
  }

  curr_buf_p = axc_bundle_get_signed_pre_key(axcbundle_p);
  ret_val = omemo_bundle_set_signed_pre_key(omemobundle_p,
                                            axc_bundle_get_signed_pre_key_id(axcbundle_p),
                                            axc_buf_get_data(curr_buf_p),
                                            axc_buf_get_len(curr_buf_p));
  if(ret_val) {
    err_msg_dbg = g_strdup_printf("failed to set signed pre key in omemo bundle");
    goto cleanup;
  }

  curr_buf_p = axc_bundle_get_signature(axcbundle_p);
  ret_val = omemo_bundle_set_signature(omemobundle_p,
                                       axc_buf_get_data(curr_buf_p),
                                       axc_buf_get_len(curr_buf_p));
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to set signature in omemo bundle");
    goto cleanup;
  }

  curr_buf_p = axc_bundle_get_identity_key(axcbundle_p);
  ret_val = omemo_bundle_set_identity_key(omemobundle_p,
                                          axc_buf_get_data(curr_buf_p),
                                          axc_buf_get_len(curr_buf_p));
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to set public identity key in omemo bundle");
    goto cleanup;
  }

  next_p = axc_bundle_get_pre_key_list(axcbundle_p);
  while (next_p) {
    curr_buf_p = axc_buf_list_item_get_buf(next_p);
    ret_val = omemo_bundle_add_pre_key(omemobundle_p,
                                       axc_buf_list_item_get_id(next_p),
                                       axc_buf_get_data(curr_buf_p),
                                       axc_buf_get_len(curr_buf_p));
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to add public pre key to omemo bundle");
      goto cleanup;
    }
    next_p = axc_buf_list_item_get_next(next_p);
  }

  ret_val = omemo_bundle_export(omemobundle_p, &bundle_xml);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to export omemo bundle to xml");
    goto cleanup;
  }

  publish_node_bundle_p = xmlnode_from_str(bundle_xml, -1);
  jabber_pep_publish(js_p, publish_node_bundle_p);

  purple_debug_info("lurch", "%s: published own bundle for %s\n", __func__, uname);

cleanup:
  if (err_msg_dbg) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  free(uname);
  axc_context_destroy_all(axc_ctx_p);
  axc_bundle_destroy(axcbundle_p);
  omemo_bundle_destroy(omemobundle_p);
  free(bundle_xml);

  return ret_val;
}

/**
 * Parses the device ID from a received bundle update.
 *
 * @param bundle_node_ns The node name.
 * @return The ID.
 */
static uint32_t lurch_bundle_name_get_device_id(const char * bundle_node_name) {
  char ** split = (void *) 0;
  uint32_t id = 0;

  split = g_strsplit(bundle_node_name, ":", -1);
  id = strtol(split[5], (void *) 0, 0);

  g_strfreev(split);

  return id;
}

/**
 * Creates an axc session from a received bundle.
 *
 * @param uname The own username.
 * @param from The sender of the bundle.
 * @param items_p The bundle update as received in the PEP request handler.
 */
static int lurch_bundle_create_session(const char * uname,
                                       const char * from,
                                       const xmlnode * items_p,
                                       axc_context * axc_ctx_p) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  int len;
  omemo_bundle * om_bundle_p = (void *) 0;
  axc_address remote_addr = {0};
  uint32_t pre_key_id = 0;
  uint8_t * pre_key_p = (void *) 0;
  size_t pre_key_len = 0;
  uint32_t signed_pre_key_id = 0;
  uint8_t * signed_pre_key_p = (void *) 0;
  size_t signed_pre_key_len = 0;
  uint8_t * signature_p = (void *) 0;
  size_t signature_len = 0;
  uint8_t * identity_key_p = (void *) 0;
  size_t identity_key_len = 0;
  axc_buf * pre_key_buf_p = (void *) 0;
  axc_buf * signed_pre_key_buf_p = (void *) 0;
  axc_buf * signature_buf_p = (void *) 0;
  axc_buf * identity_key_buf_p = (void *) 0;

  purple_debug_info("lurch", "%s: creating a session between %s and %s from a received bundle\n", __func__, uname, from);

  ret_val = omemo_bundle_import(xmlnode_to_str(items_p, &len), &om_bundle_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to import xml into bundle");
    goto cleanup;
  }

  remote_addr.name = from;
  remote_addr.name_len = strnlen(from, JABBER_MAX_LEN_BARE);
  remote_addr.device_id = omemo_bundle_get_device_id(om_bundle_p);

  purple_debug_info("lurch", "%s: bundle's device id is %i\n", __func__, remote_addr.device_id);

  ret_val = omemo_bundle_get_random_pre_key(om_bundle_p, &pre_key_id, &pre_key_p, &pre_key_len);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed get a random pre key from the bundle");
    goto cleanup;
  }
  ret_val = omemo_bundle_get_signed_pre_key(om_bundle_p, &signed_pre_key_id, &signed_pre_key_p, &signed_pre_key_len);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get the signed pre key from the bundle");
    goto cleanup;
  }
  ret_val = omemo_bundle_get_signature(om_bundle_p, &signature_p, &signature_len);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get the signature from the bundle");
    goto cleanup;
  }
  ret_val = omemo_bundle_get_identity_key(om_bundle_p, &identity_key_p, &identity_key_len);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get the public identity key from the bundle");
    goto cleanup;
  }

  pre_key_buf_p = axc_buf_create(pre_key_p, pre_key_len);
  signed_pre_key_buf_p = axc_buf_create(signed_pre_key_p, signed_pre_key_len);
  signature_buf_p = axc_buf_create(signature_p, signature_len);
  identity_key_buf_p = axc_buf_create(identity_key_p, identity_key_len);

  if (!pre_key_buf_p || !signed_pre_key_buf_p || !signature_buf_p || !identity_key_buf_p) {
    ret_val = LURCH_ERR;
    err_msg_dbg = g_strdup_printf("failed to create one of the buffers");
    goto cleanup;
  }

  ret_val = axc_session_from_bundle(pre_key_id, pre_key_buf_p,
                                    signed_pre_key_id, signed_pre_key_buf_p,
                                    signature_buf_p,
                                    identity_key_buf_p,
                                    &remote_addr,
                                    axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to create a session from a bundle");
    goto cleanup;
  }

cleanup:
  if (err_msg_dbg) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  omemo_bundle_destroy(om_bundle_p);
  free(pre_key_p);
  free(signed_pre_key_p);
  free(signature_p);
  free(identity_key_p);
  axc_buf_free(pre_key_buf_p);
  axc_buf_free(signed_pre_key_buf_p);
  axc_buf_free(signature_buf_p);
  axc_buf_free(identity_key_buf_p);

  return ret_val;
}

/**
 * Implements JabberIqCallback.
 * Callback for a bundle request.
 */
static void lurch_bundle_request_cb(JabberStream * js_p, const char * from,
                                    JabberIqType type, const char * id,
                                    xmlnode * packet_p, gpointer data_p) {
  int ret_val = 0;
  char * err_msg_conv = (void *) 0;
  char * err_msg_dbg = (void *) 0;

  char * uname = (void *) 0;
  char ** split = (void *) 0;
  char * device_id_str = (void *) 0;
  axc_address addr = {0};
  axc_context * axc_ctx_p = (void *) 0;
  char * recipient = (void *) 0;
  xmlnode * pubsub_node_p = (void *) 0;
  xmlnode * items_node_p = (void *) 0;
  int msg_handled = 0;
  char * addr_key = (void *) 0;
  char * msg_xml = (void *) 0;
  xmlnode * msg_node_p = (void *) 0;
  lurch_queued_msg * qmsg_p = (lurch_queued_msg *) data_p;

  uname = lurch_uname_strip(purple_account_get_username(purple_connection_get_account(js_p->gc)));
  recipient = omemo_message_get_recipient_name_bare(qmsg_p->om_msg_p);

  if (!from) {
    // own user
    from = uname;
  }

  split = g_strsplit(id, "#", 3);
  device_id_str = split[1];

  purple_debug_info("lurch", "%s: %s received bundle update from %s:%s\n", __func__, uname, from, device_id_str);

  addr.name = from;
  addr.name_len = strnlen(from, JABBER_MAX_LEN_BARE);
  addr.device_id = strtol(device_id_str, (void *) 0, 10);

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = "failed to get axc ctx";
    goto cleanup;
  }

  if (type == JABBER_IQ_ERROR) {
    err_msg_conv = g_strdup_printf("The device %s owned by %s does not have a bundle and will be skipped. "
                                   "The owner should fix this, or remove the device from the list.", device_id_str, from);

  } else {
    pubsub_node_p = xmlnode_get_child(packet_p, "pubsub");
    if (!pubsub_node_p) {
      ret_val = LURCH_ERR;
      err_msg_dbg = "no <pubsub> node in response";
      goto cleanup;
    }

    items_node_p = xmlnode_get_child(pubsub_node_p, "items");
    if (!items_node_p) {
      ret_val = LURCH_ERR;
      err_msg_dbg = "no <items> node in response";
      goto cleanup;
    }

    ret_val = axc_session_exists_initiated(&addr, axc_ctx_p);
    if (!ret_val) {
      ret_val = lurch_bundle_create_session(uname, from, items_node_p, axc_ctx_p);
      if (ret_val) {
        err_msg_dbg = "failed to create a session";
        goto cleanup;
      }
    } else if (ret_val < 0) {
      err_msg_dbg = "failed to check if session exists";
      goto cleanup;
    }
  }

  addr_key = lurch_queue_make_key_string_s(from, device_id_str);
  if (!addr_key) {
    err_msg_dbg = "failed to make a key string";
    ret_val = LURCH_ERR;
    goto cleanup;
  }

  (void) g_hash_table_replace(qmsg_p->sess_handled_p, addr_key, addr_key);

  if (lurch_queued_msg_is_handled(qmsg_p)) {
    msg_handled = 1;
  }

  if (msg_handled) {
    ret_val = lurch_msg_encrypt_for_addrs(qmsg_p->om_msg_p, qmsg_p->recipient_addr_l_p, axc_ctx_p);
    if (ret_val) {
      err_msg_dbg = "failed to encrypt the symmetric key";
      goto cleanup;
    }

    ret_val = omemo_message_export_encrypted(qmsg_p->om_msg_p, &msg_xml);
    if (ret_val) {
      err_msg_dbg = "failed to export the message to xml";
      goto cleanup;
    }

    msg_node_p = xmlnode_from_str(msg_xml, -1);
    if (!msg_node_p) {
      err_msg_dbg = "failed to parse xml from string";
      ret_val = LURCH_ERR;
      goto cleanup;
    }

    purple_debug_info("lurch", "sending encrypted msg\n");
    purple_signal_emit(purple_plugins_find_with_id("prpl-jabber"), "jabber-sending-xmlnode", js_p->gc, &msg_node_p);

    lurch_queued_msg_destroy(qmsg_p);
  }

cleanup:
  if (err_msg_conv) {
    purple_conv_present_error(recipient, purple_connection_get_account(js_p->gc), err_msg_conv);
    g_free(err_msg_conv);
  }
  if (err_msg_dbg) {
    purple_conv_present_error(recipient, purple_connection_get_account(js_p->gc), LURCH_ERR_STRING_ENCRYPT);
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
  }

  free(uname);
  g_strfreev(split);
  axc_context_destroy_all(axc_ctx_p);
  free(addr_key);
  free(recipient);
  free(msg_xml);
  if (msg_node_p) {
    xmlnode_free(msg_node_p);
  }
}

/**
 * Requests a bundle.
 *
 * @param js_p Pointer to the JabberStream to use.
 * @param to The recipient of this request.
 * @param device_id The ID of the device whose bundle is needed.
 * @param qmsg_p Pointer to the queued message waiting on (at least) this bundle.
 * @return 0 on success, negative on error.
 */
static int lurch_bundle_request_do(JabberStream * js_p,
                                   const char * to,
                                   uint32_t device_id,
                                   lurch_queued_msg * qmsg_p) {
  int ret_val = 0;

  JabberIq * jiq_p = (void *) 0;
  xmlnode * pubsub_node_p = (void *) 0;
  char * device_id_str = (void *) 0;
  char * rand_str = (void *) 0;
  char * req_id = (void *) 0;
  char * bundle_node_name = (void *) 0;
  xmlnode * items_node_p = (void *) 0;

  purple_debug_info("lurch", "%s: %s is requesting bundle from %s:%i\n", __func__,
                    purple_account_get_username(purple_connection_get_account(js_p->gc)), to, device_id);

  jiq_p = jabber_iq_new(js_p, JABBER_IQ_GET);
  xmlnode_set_attrib(jiq_p->node, "to", to);

  pubsub_node_p = xmlnode_new_child(jiq_p->node, "pubsub");
  xmlnode_set_namespace(pubsub_node_p, "http://jabber.org/protocol/pubsub");

  device_id_str = g_strdup_printf("%i", device_id);
  rand_str = g_strdup_printf("%i", g_random_int());
  req_id = g_strconcat(to, "#", device_id_str, "#", rand_str, NULL);

  ret_val = omemo_bundle_get_pep_node_name(device_id, &bundle_node_name);
  if (ret_val) {
    purple_debug_error("lurch", "%s: failed to get bundle pep node name for %s:%i\n", __func__, to, device_id);
    goto cleanup;
  }

  items_node_p = xmlnode_new_child(pubsub_node_p, "items");
  xmlnode_set_attrib(items_node_p, "node", bundle_node_name);
  xmlnode_set_attrib(items_node_p, "max_items", "1");

  jabber_iq_set_id(jiq_p, req_id);
  jabber_iq_set_callback(jiq_p, lurch_bundle_request_cb, qmsg_p);

  jabber_iq_send(jiq_p);

  purple_debug_info("lurch", "%s: ...request sent\n", __func__);

cleanup:
  g_free(device_id_str);
  g_free(rand_str);
  g_free(req_id);
  g_free(bundle_node_name);

  return ret_val;
}

/**
 * A JabberPEPHandler function.
 * When a prekey message containing an invalid key ID is received,
 * the bundle of the sender is requested and a KeyTransport message is sent
 * in response so that a session can still be established.
 */
static void lurch_pep_bundle_for_keytransport(JabberStream * js_p, const char * from, xmlnode * items_p) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  char * uname = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t own_id = 0;
  omemo_message * msg_p = (void *) 0;
  axc_address addr = {0};
  lurch_addr laddr = {0};
  axc_buf * key_ct_buf_p = (void *) 0;
  char * msg_xml = (void *) 0;
  xmlnode * msg_node_p = (void *) 0;
  void * jabber_handle_p = purple_plugins_find_with_id("prpl-jabber");

  uname = lurch_uname_strip(purple_account_get_username(purple_connection_get_account(js_p->gc)));

  addr.name = from;
  addr.name_len = strnlen(from, JABBER_MAX_LEN_BARE);
  addr.device_id = lurch_bundle_name_get_device_id(xmlnode_get_attrib(items_p, "node"));

  purple_debug_info("lurch", "%s: %s received bundle from %s:%i\n", __func__, uname, from, addr.device_id);

  laddr.jid = g_strndup(addr.name, addr.name_len);
  laddr.device_id = addr.device_id;

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to init axc ctx");
    goto cleanup;
  }

  // make sure it's gonna be a pre_key_message
  ret_val = axc_session_delete(addr.name, addr.device_id, axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to delete possibly existing session");
    goto cleanup;
  }

  ret_val = lurch_bundle_create_session(uname, from, items_p, axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to create session");
    goto cleanup;
  }

  purple_debug_info("lurch", "%s: %s created session with %s:%i\n", __func__, uname, from, addr.device_id);

  ret_val = axc_get_device_id(axc_ctx_p, &own_id);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get own device id");
    goto cleanup;
  }

  ret_val = omemo_message_create(own_id, &crypto, &msg_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to create omemo msg");
    goto cleanup;
  }

  ret_val = lurch_key_encrypt(&laddr,
                              omemo_message_get_key(msg_p),
                              omemo_message_get_key_len(msg_p),
                              axc_ctx_p,
                              &key_ct_buf_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to encrypt key for %s:%i", addr.name, addr.device_id);
    goto cleanup;
  }

  ret_val = omemo_message_add_recipient(msg_p,
                                        addr.device_id,
                                        axc_buf_get_data(key_ct_buf_p),
                                        axc_buf_get_len(key_ct_buf_p));
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to add %s:%i as recipient to message", addr.name, addr.device_id);
    goto cleanup;
  }

  ret_val = omemo_message_export_encrypted(msg_p, &msg_xml);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to export encrypted msg");
    goto cleanup;
  }

  msg_node_p = xmlnode_from_str(msg_xml, -1);
  if (!msg_node_p) {
    err_msg_dbg = g_strdup_printf("failed to create xml node from xml string");
    goto cleanup;
  }

  purple_signal_emit(jabber_handle_p, "jabber-sending-xmlnode", js_p->gc, &msg_node_p);
  purple_debug_info("lurch", "%s: %s sent keytransportmsg to %s:%i\n", __func__, uname, from, addr.device_id);


cleanup:
  if (err_msg_dbg) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  free(laddr.jid);
  free(uname);
  axc_context_destroy_all(axc_ctx_p);
  omemo_message_destroy(msg_p);
  axc_buf_free(key_ct_buf_p);
  free(msg_xml);
  if (msg_node_p) {
    xmlnode_free(msg_node_p);
  }
}

/**
 * Processes a devicelist by updating the database with it.
 *
 * @param uname The username.
 * @param dl_in_p Pointer to the incoming devicelist.
 * @param js_p Pointer to the JabberStream.
 * @return 0 on success, negative on error.
 */
static int lurch_devicelist_process(char * uname, omemo_devicelist * dl_in_p, JabberStream * js_p) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  const char * from = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  omemo_devicelist * dl_db_p = (void *) 0;
  GList * add_l_p = (void *) 0;
  GList * del_l_p = (void *) 0;
  GList * curr_p = (void *) 0;
  uint32_t curr_id = 0;
  char * bundle_node_name = (void *) 0;

  char * temp;

  from = omemo_devicelist_get_owner(dl_in_p);
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  purple_debug_info("lurch", "%s: processing devicelist from %s for %s\n", __func__, from, uname);

  ret_val = omemo_storage_user_devicelist_retrieve(from, db_fn_omemo, &dl_db_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to retrieve cached devicelist for %s from db %s", from, db_fn_omemo);
    goto cleanup;
  }

  omemo_devicelist_export(dl_db_p, &temp);
  purple_debug_info("lurch", "%s: %s\n%s\n", __func__, "cached devicelist is", temp);

  ret_val = omemo_devicelist_diff(dl_in_p, dl_db_p, &add_l_p, &del_l_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to diff devicelists");
    goto cleanup;
  }

  for (curr_p = add_l_p; curr_p; curr_p = curr_p->next) {
    curr_id = omemo_devicelist_list_data(curr_p);
    purple_debug_info("lurch", "%s: saving %i for %s to db %s\n", __func__, curr_id, from, db_fn_omemo);
    ret_val = omemo_storage_user_device_id_save(from, curr_id, db_fn_omemo);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to save %i for %s to %s", curr_id, from, db_fn_omemo);
      goto cleanup;
    }
  }

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to init axc ctx");
    goto cleanup;
  }

  for (curr_p = del_l_p; curr_p; curr_p = curr_p->next) {
    curr_id = omemo_devicelist_list_data(curr_p);
    purple_debug_info("lurch", "%s: deleting %i for %s to db %s\n", __func__, curr_id, from, db_fn_omemo);

    ret_val = omemo_storage_user_device_id_delete(from, curr_id, db_fn_omemo);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to delete %i for %s from %s", curr_id, from, db_fn_omemo);
      goto cleanup;
    }
  }

cleanup:
  if (err_msg_dbg) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  free(db_fn_omemo);
  omemo_devicelist_destroy(dl_db_p);
  axc_context_destroy_all(axc_ctx_p);
  g_list_free_full(add_l_p, free);
  g_list_free_full(del_l_p, free);
  free(bundle_node_name);
  free(temp);

  return ret_val;
}

/**
 * A JabberPEPHandler function.
 * Is used to handle the own devicelist and also perform install-time functions.
 */
static void lurch_pep_own_devicelist_request_handler(JabberStream * js_p, const char * from, xmlnode * items_p) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  int len = 0;
  PurpleAccount * acc_p = (void *) 0;
  char * uname = (void *) 0;
  int install = 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t own_id = 0;
  int needs_publishing = 1;
  omemo_devicelist * dl_p = (void *) 0;
  char * dl_xml = (void *) 0;
  xmlnode * publish_node_dl_p = (void *) 0;

  acc_p = purple_connection_get_account(js_p->gc);
  uname = lurch_uname_strip(purple_account_get_username(acc_p));

  install = (purple_account_get_bool(acc_p, LURCH_ACC_SETTING_INITIALIZED, FALSE)) ? 0 : 1;

  if (install && !uninstall) {
    purple_debug_info("lurch", "%s: %s\n", __func__, "preparing installation...");
    ret_val = lurch_axc_prepare(uname);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to prepare axc");
      goto cleanup;
    }
    purple_debug_info("lurch", "%s: %s\n", __func__, "...done");
  }

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to init axc ctx");
    goto cleanup;
  }
  ret_val = axc_get_device_id(axc_ctx_p, &own_id);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get own id");
    goto cleanup;
  }

  if (!items_p) {
    purple_debug_info("lurch", "%s: %s\n", __func__, "no devicelist yet, creating it");
    ret_val = omemo_devicelist_create(uname, &dl_p);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to create devicelist");
      goto cleanup;
    }
    ret_val = omemo_devicelist_add(dl_p, own_id);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to add own id %i to devicelist", own_id);
      goto cleanup;
    }
  } else {
    purple_debug_info("lurch", "%s: %s\n", __func__, "comparing received devicelist with cached one");
    ret_val = omemo_devicelist_import(xmlnode_to_str(items_p, &len), uname, &dl_p);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to import received devicelist");
      goto cleanup;
    }

    ret_val = omemo_devicelist_contains_id(dl_p, own_id);
    if (ret_val == 1) {
      purple_debug_info("lurch", "%s: %s\n", __func__, "own id was already contained in received devicelist, doing nothing");
      needs_publishing = 0;
    } else if (ret_val == 0) {
      if (!uninstall) {
        purple_debug_info("lurch", "%s: %s\n", __func__, "own id was missing, adding it");
        ret_val = omemo_devicelist_add(dl_p, own_id);
        if (ret_val) {
          err_msg_dbg = g_strdup_printf("failed to add own id %i to devicelist", own_id);
          goto cleanup;
        }
      } else {
        needs_publishing = 0;
      }

    } else {
      err_msg_dbg = g_strdup_printf("failed to look up if the devicelist contains the own id");
      goto cleanup;
    }
  }

  if (needs_publishing) {
    purple_debug_info("lurch", "%s: %s\n", __func__, "devicelist needs publishing...");
    ret_val = omemo_devicelist_export(dl_p, &dl_xml);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to export new devicelist");
      goto cleanup;
    }

    publish_node_dl_p = xmlnode_from_str(dl_xml, -1);
    jabber_pep_publish(js_p, publish_node_dl_p);

    purple_debug_info("lurch", "%s: \n%s:\n", __func__, "...done");
  }

  ret_val = lurch_bundle_publish_own(js_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to publish own bundle");
    goto cleanup;
  }

  if (install && !uninstall) {
    purple_account_set_bool(acc_p, LURCH_ACC_SETTING_INITIALIZED, TRUE);
  }

  ret_val = lurch_devicelist_process(uname, dl_p, js_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to process the devicelist");
    goto cleanup;
  }

cleanup:
  if (err_msg_dbg) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }
  g_free(uname);
  axc_context_destroy_all(axc_ctx_p);
  omemo_devicelist_destroy(dl_p);
  free(dl_xml);
}

/**
 * A JabberPEPHandler function.
 * On receiving a devicelist PEP update it updated the database.
 */
static void lurch_pep_devicelist_event_handler(JabberStream * js_p, const char * from, xmlnode * items_p) {
  int ret_val = 0;
  int len = 0;
  char * err_msg_dbg = (void *) 0;

  char * uname = (void *) 0;
  omemo_devicelist * dl_in_p = (void *) 0;

  uname = lurch_uname_strip(purple_account_get_username(purple_connection_get_account(js_p->gc)));
  if (!strncmp(uname, from, strnlen(uname, JABBER_MAX_LEN_BARE))) {
    //own devicelist is dealt with in own handler
    lurch_pep_own_devicelist_request_handler(js_p, from, items_p);
    goto cleanup;
  }

  purple_debug_info("lurch", "%s: %s received devicelist update from %s\n", __func__, uname, from);

  ret_val = omemo_devicelist_import(xmlnode_to_str(items_p, &len), from, &dl_in_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to import devicelist");
    goto cleanup;
  }



  ret_val = lurch_devicelist_process(uname, dl_in_p, js_p);
  if(ret_val) {
    err_msg_dbg = g_strdup_printf("failed to process devicelist");
    goto cleanup;
  }

cleanup:
  if (err_msg_dbg) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    g_free(err_msg_dbg);
  }
  g_free(uname);
  omemo_devicelist_destroy(dl_in_p);
}

/**
 * Set as callback for the "account connected" signal.
 * Requests the own devicelist, as that requires an active connection (as
 * opposed to just registering PEP handlers).
 * Also inits the msg queue hashtable.
 */
static void lurch_account_connect_cb(PurpleAccount * acc_p) {
  int ret_val = 0;

  char * uname = (void *) 0;
  JabberStream * js_p = (void *) 0;
  char * dl_ns = (void *) 0;

 // purple_account_set_bool(acc_p, LURCH_ACC_SETTING_INITIALIZED, FALSE);

  js_p = purple_connection_get_protocol_data(purple_account_get_connection(acc_p));

  if (strncmp(purple_account_get_protocol_id(acc_p), JABBER_PROTOCOL_ID, strlen(JABBER_PROTOCOL_ID))) {
    return;
  }

  ret_val = omemo_devicelist_get_pep_node_name(&dl_ns);
  if (ret_val) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, "failed to get devicelist pep node name", ret_val);
    goto cleanup;
  }
  uname = lurch_uname_strip(purple_account_get_username(acc_p));
  jabber_pep_request_item(js_p, uname, dl_ns, (void *) 0, lurch_pep_own_devicelist_request_handler);

cleanup:
  g_free(uname);
  free(dl_ns);
}

/**
 * For a list of lurch_addrs, checks which ones do not have an active session.
 * Note that the structs are not copied, the returned list is just a subset
 * of the pointers of the input list.
 *
 * @param addr_l_p A list of pointers to lurch_addr structs.
 * @param axc_ctx_p The axc_context to use.
 * @param no_sess_l_pp Will point to a list that contains pointers to those
 *                     addresses that do not have a session.
 * @return 0 on success, negative on error.
 */
static int lurch_axc_sessions_exist(GList * addr_l_p, axc_context * axc_ctx_p, GList ** no_sess_l_pp){
  int ret_val = 0;

  GList * no_sess_l_p = (void *) 0;

  GList * curr_p;
  lurch_addr * curr_addr_p;
  axc_address curr_axc_addr = {0};
  for (curr_p = addr_l_p; curr_p; curr_p = curr_p->next) {
    curr_addr_p = (lurch_addr *) curr_p->data;

    curr_axc_addr.name = curr_addr_p->jid;
    curr_axc_addr.name_len = strnlen(curr_axc_addr.name, JABBER_MAX_LEN_BARE);
    curr_axc_addr.device_id = curr_addr_p->device_id;

    ret_val = axc_session_exists_initiated(&curr_axc_addr, axc_ctx_p);
    if (ret_val < 0) {
      purple_debug_error("lurch", "%s: %s (%i)\n", __func__, "failed to see if session exists", ret_val);
      goto cleanup;
    } else if (ret_val > 0) {
      ret_val = 0;
      continue;
    } else {
      no_sess_l_p = g_list_prepend(no_sess_l_p, curr_addr_p);
      ret_val = 0;
    }
  }

  *no_sess_l_pp = no_sess_l_p;

cleanup:
  return ret_val;
}

/**
 * Adds an omemo devicelist to a GList of lurch_addrs.
 *
 * @param addrs_p Pointer to the list to add to. Remember NULL is a valid GList *.
 * @param dl_p Pointer to the omemo devicelist to add.
 * @param exclude_id_p Pointer to an ID that is not to be added. Useful when adding the own devicelist. Can be NULL.
 * @return Pointer to the updated GList on success, NULL on error.
 */
static GList * lurch_addr_list_add(GList * addrs_p, const omemo_devicelist * dl_p, const uint32_t * exclude_id_p) {
  int ret_val = 0;

  GList * new_l_p = addrs_p;
  GList * dl_l_p = (void *) 0;
  GList * curr_p = (void *) 0;
  lurch_addr curr_addr = {0};
  uint32_t curr_id = 0;
  lurch_addr * temp_addr_p = (void *) 0;

  curr_addr.jid = g_strdup(omemo_devicelist_get_owner(dl_p));

  dl_l_p = omemo_devicelist_get_id_list(dl_p);

  for (curr_p = dl_l_p; curr_p; curr_p = curr_p->next) {
    curr_id = omemo_devicelist_list_data(curr_p);
    if (exclude_id_p && *exclude_id_p == curr_id) {
      continue;
    }

    curr_addr.device_id = curr_id;

    temp_addr_p = malloc(sizeof(lurch_addr));
    if (!temp_addr_p) {
      ret_val = LURCH_ERR_NOMEM;
      goto cleanup;
    }

    memcpy(temp_addr_p, &curr_addr, sizeof(lurch_addr));

    new_l_p = g_list_prepend(new_l_p, temp_addr_p);
  }

cleanup:
  g_list_free_full(dl_l_p, free);

  if (ret_val) {
    g_list_free_full(new_l_p, lurch_addr_list_destroy_func);
    return (void *) 0;
  } else {
    return new_l_p;
  }
}

/**
 * Does the final steps of encrypting the message.
 * If all devices have sessions, does the actual encrypting.
 * If not, saves it and sends bundle request to the missing devices so that the message can be sent at a later time.
 *
 * Note that if msg_stanza_pp points to NULL, both om_msg_p and addr_l_p must not be freed by the calling function.
 *
 * @param js_p          Pointer to the JabberStream to use.
 * @param axc_ctx_p     Pointer to the axc_context to use.
 * @param om_msg_p      Pointer to the omemo message.
 * @param addr_l_p      Pointer to a GList of lurch_addr structs that are supposed to receive the message.
 * @param msg_stanza_pp Pointer to the pointer to the <message> stanza.
 *                      Is either changed to point to the encrypted message, or to NULL if the message is to be sent later.
 * @return 0 on success, negative on error.
 *
 */
static int lurch_msg_finalize_encryption(JabberStream * js_p, axc_context * axc_ctx_p, omemo_message * om_msg_p, GList * addr_l_p, xmlnode ** msg_stanza_pp) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  GList * no_sess_l_p = (void *) 0;
  char * xml = (void *) 0;
  xmlnode * temp_node_p = (void *) 0;
  lurch_queued_msg * qmsg_p = (void *) 0;
  GList * curr_item_p = (void *) 0;
  lurch_addr curr_addr = {0};
  char * bundle_node_name = (void *) 0;

  ret_val = lurch_axc_sessions_exist(addr_l_p, axc_ctx_p, &no_sess_l_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to check if sessions exist");
    goto cleanup;
  }

  if (!no_sess_l_p) {
    ret_val = lurch_msg_encrypt_for_addrs(om_msg_p, addr_l_p, axc_ctx_p);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to encrypt symmetric key for addrs");
      goto cleanup;
    }

    ret_val = omemo_message_export_encrypted(om_msg_p, &xml);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to export omemo msg to xml");
      goto cleanup;
    }

    temp_node_p = xmlnode_from_str(xml, -1);
    *msg_stanza_pp = temp_node_p;
  } else {
    ret_val = lurch_queued_msg_create(om_msg_p, addr_l_p, no_sess_l_p, &qmsg_p);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to create queued message");
      goto cleanup;
    }

    for (curr_item_p = no_sess_l_p; curr_item_p; curr_item_p = curr_item_p->next) {
      curr_addr.jid = ((lurch_addr *)curr_item_p->data)->jid;
      curr_addr.device_id = ((lurch_addr *)curr_item_p->data)->device_id;

      purple_debug_info("lurch", "%s: %s has device without session %i, requesting bundle\n", __func__, curr_addr.jid, curr_addr.device_id);

      ret_val = omemo_bundle_get_pep_node_name(curr_addr.device_id, &bundle_node_name);
      if (ret_val) {
        err_msg_dbg = g_strdup_printf("failed to get pep node name");
        goto cleanup;
      }

      lurch_bundle_request_do(js_p,
                              curr_addr.jid,
                              curr_addr.device_id,
                              qmsg_p);

    }
    *msg_stanza_pp = (void *) 0;
  }

cleanup:
  if (err_msg_dbg) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
    *msg_stanza_pp = (void *) 0;
  }
  if (!qmsg_p || ret_val) {
    free(qmsg_p);
  }

  free(xml);
  free(bundle_node_name);

  return ret_val;
}


/**
 * Set as callback for the "sending xmlnode" signal.
 * Encrypts the message body, if applicable.
 */
static void lurch_message_encrypt_im(PurpleConnection * gc_p, xmlnode ** msg_stanza_pp) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;
  int len = 0;

  PurpleAccount * acc_p = (void *) 0;
  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  const char * to = (void *) 0;
  omemo_devicelist * dl_p = (void *) 0;
  GList * recipient_dl_p = (void *) 0;
  omemo_devicelist * user_dl_p = (void *) 0;
  GList * own_dl_p = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t own_id = 0;
  omemo_message * msg_p = (void *) 0;
  GList * addr_l_p = (void *) 0;
  char * recipient = (void *) 0;
  char * tempxml = (void *) 0;

  recipient = jabber_get_bare_jid(xmlnode_get_attrib(*msg_stanza_pp, "to"));

  acc_p = purple_connection_get_account(gc_p);
  uname = lurch_uname_strip(purple_account_get_username(acc_p));
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = omemo_storage_chatlist_exists(recipient, db_fn_omemo);
  if (ret_val < 0) {
    err_msg_dbg = g_strdup_printf("failed to look up %s in DB %s", recipient, db_fn_omemo);
    goto cleanup;
  } else if (ret_val == 1) {
    purple_debug_info("lurch", "%s: %s is on blacklist, skipping encryption\n", __func__, recipient);
    goto cleanup;
  }

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get axc ctx for %s", uname);
    goto cleanup;
  }

  ret_val = axc_get_device_id(axc_ctx_p, &own_id);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get device id");
    goto cleanup;
  }
  tempxml = xmlnode_to_str(*msg_stanza_pp, &len);
  ret_val = omemo_message_prepare_encryption(tempxml, own_id, &crypto, &msg_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to construct omemo message");
    goto cleanup;
  }

  to = omemo_message_get_recipient_name_bare(msg_p);

  // determine if recipient is omemo user
  ret_val = omemo_storage_user_devicelist_retrieve(to, db_fn_omemo, &dl_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to retrieve devicelist for %s", to);
    goto cleanup;
  }

  free(tempxml);
  ret_val = omemo_devicelist_export(dl_p, &tempxml);
  if(ret_val) {
    err_msg_dbg = g_strdup_printf("failed to export devicelist for %s", to);
    goto cleanup;
  }
  purple_debug_info("lurch", "retrieved devicelist for %s:\n%s\n", to, tempxml);

  recipient_dl_p = omemo_devicelist_get_id_list(dl_p);
  if (!recipient_dl_p) {
    ret_val = axc_session_exists_any(to, axc_ctx_p);
    if (ret_val < 0) {
      err_msg_dbg = g_strdup_printf("failed to check if session exists for %s in %s's db\n", to, uname);
      goto cleanup;
    } else if (ret_val == 1) {
      purple_conv_present_error(recipient, purple_connection_get_account(gc_p), "Even though an encrypted session exists, the recipient's devicelist is empty."
                                                                                "The user probably uninstalled OMEMO, so you can add this conversation to the blacklist.");
    } else {
      goto cleanup;
    }
  }

  ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &user_dl_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to retrieve devicelist for %s", uname);
    goto cleanup;
  }
  omemo_devicelist_export(user_dl_p, &tempxml);
  purple_debug_info("lurch", "retrieved own devicelist:\n%s\n", tempxml);
  own_dl_p = omemo_devicelist_get_id_list(user_dl_p);
  if (!own_dl_p) {
    err_msg_dbg = g_strdup_printf("no own devicelist");
    goto cleanup;
  }

  addr_l_p = lurch_addr_list_add(addr_l_p, user_dl_p, &own_id);
  addr_l_p = lurch_addr_list_add(addr_l_p, dl_p, (void *) 0);
  if (!addr_l_p) {
    err_msg_dbg = g_strdup_printf("failed to malloc address struct");
    ret_val = LURCH_ERR_NOMEM;
    goto cleanup;
  }

  ret_val = lurch_msg_finalize_encryption(purple_connection_get_protocol_data(gc_p), axc_ctx_p, msg_p, addr_l_p, msg_stanza_pp);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to finalize omemo message");
    goto cleanup;
  }

cleanup:
  if (err_msg_dbg) {
    purple_conv_present_error(recipient, purple_connection_get_account(gc_p), LURCH_ERR_STRING_ENCRYPT);
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
    *msg_stanza_pp = (void *) 0;
  }
  if (ret_val) {
    omemo_message_destroy(msg_p);
    g_list_free_full(addr_l_p, lurch_addr_list_destroy_func);
  }
  free(recipient);
  free(uname);
  free(db_fn_omemo);
  omemo_devicelist_destroy(dl_p);
  g_list_free_full(recipient_dl_p, free);
  omemo_devicelist_destroy(user_dl_p);
  g_list_free_full(own_dl_p, free);
  axc_context_destroy_all(axc_ctx_p);
  free(tempxml);
}

static void lurch_message_encrypt_groupchat(PurpleConnection * gc_p, xmlnode ** msg_stanza_pp) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;
  int len;

  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t own_id = 0;
  char * tempxml = (void *) 0;
  omemo_message * om_msg_p = (void *) 0;
  omemo_devicelist * user_dl_p = (void *) 0;
  GList * addr_l_p = (void *) 0;
  PurpleConversation * conv_p = (void *) 0;
  PurpleConvChat * chat_p = (void *) 0;
  xmlnode * body_node_p = (void *) 0;
  PurpleConvChatBuddy * curr_buddy_p = (void *) 0;
  GHashTable * nick_jid_ht_p = (void *) 0;
  GList * curr_item_p = (void *) 0;
  char * curr_buddy_jid = (void *) 0;
  omemo_devicelist * curr_dl_p = (void *) 0;

  uname = lurch_uname_strip(purple_account_get_username(purple_connection_get_account(gc_p)));
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = omemo_storage_chatlist_exists(xmlnode_get_attrib(*msg_stanza_pp, "to"), db_fn_omemo);
  if (ret_val < 0) {
    err_msg_dbg = g_strdup_printf("failed to access db %s", db_fn_omemo);
    goto cleanup;
  } else if (ret_val == 0) {
    goto cleanup;
  }

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get axc ctx for %s", uname);
    goto cleanup;
  }

  ret_val = axc_get_device_id(axc_ctx_p, &own_id);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get device id");
    goto cleanup;
  }
  tempxml = xmlnode_to_str(*msg_stanza_pp, &len);
  ret_val = omemo_message_prepare_encryption(tempxml, own_id, &crypto, &om_msg_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to construct omemo message");
    goto cleanup;
  }

  ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &user_dl_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to retrieve devicelist for %s", uname);
    goto cleanup;
  }

  addr_l_p = lurch_addr_list_add(addr_l_p, user_dl_p, &own_id);

  conv_p = purple_find_conversation_with_account(2, xmlnode_get_attrib(*msg_stanza_pp, "to"), purple_connection_get_account(gc_p));
  if (!conv_p) {
    err_msg_dbg = g_strdup_printf("could not find groupchat %s", xmlnode_get_attrib(*msg_stanza_pp, "to"));
    goto cleanup;
  }

  chat_p = purple_conversation_get_chat_data(conv_p);

  nick_jid_ht_p = g_hash_table_lookup(chat_users_ht_p, purple_conversation_get_name(conv_p));
  if (!nick_jid_ht_p) {
    err_msg_dbg = g_strdup_printf("no entry in ht for %s!\n", purple_conversation_get_name(conv_p));
    goto cleanup;
  }

  for (curr_item_p = purple_conv_chat_get_users(chat_p); curr_item_p; curr_item_p = curr_item_p->next) {
    curr_buddy_p = (PurpleConvChatBuddy *) curr_item_p->data;
    curr_buddy_jid = g_hash_table_lookup(nick_jid_ht_p, curr_buddy_p->name);
    if (!curr_buddy_jid) {
      err_msg_dbg = g_strdup_printf("Could not find the JID for %s - the channel needs to be non-anonymous!", curr_buddy_p->name);
      purple_conv_present_error(purple_conversation_get_name(conv_p), purple_connection_get_account(gc_p), err_msg_dbg);
      g_free(err_msg_dbg);
      err_msg_dbg = (void *) 0;
      continue;
    }

    if (!g_strcmp0(curr_buddy_jid, uname)) {
      body_node_p = xmlnode_get_child(*msg_stanza_pp, "body");

      purple_conv_chat_write(chat_p, curr_buddy_p->name, xmlnode_get_data(body_node_p), PURPLE_MESSAGE_SEND, time((void *) 0));
      continue;
    }

    ret_val = omemo_storage_user_devicelist_retrieve(curr_buddy_jid, db_fn_omemo, &curr_dl_p);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("Could not retrieve the deviceilist for %s from %s", curr_buddy_jid, db_fn_omemo);
      goto cleanup;
    }

    if (omemo_devicelist_is_empty(curr_dl_p)) {
      err_msg_dbg = g_strdup_printf("User %s is no OMEMO user (has no devicelist). "
                                    "This user cannot read any incoming encrypted messages and will send his own messages in the clear!",
                                    curr_buddy_p->name);
      purple_conv_present_error(purple_conversation_get_name(conv_p), purple_connection_get_account(gc_p), err_msg_dbg);
      g_free(err_msg_dbg);
      err_msg_dbg = (void *) 0;
      continue;
    }

    addr_l_p = lurch_addr_list_add(addr_l_p, curr_dl_p, (void *) 0);
    omemo_devicelist_destroy(curr_dl_p);
    curr_dl_p = (void *) 0;
  }

  ret_val = lurch_msg_finalize_encryption(purple_connection_get_protocol_data(gc_p), axc_ctx_p, om_msg_p, addr_l_p, msg_stanza_pp);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to finalize msg");
    goto cleanup;
  }

  body_node_p = xmlnode_get_child(*msg_stanza_pp, "body");
  xmlnode_free(body_node_p);

cleanup:
  if (err_msg_dbg) {
    purple_conv_present_error(purple_conversation_get_name(conv_p), purple_connection_get_account(gc_p), LURCH_ERR_STRING_ENCRYPT);
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
    *msg_stanza_pp = (void *) 0;
  }
  if (ret_val) {
    omemo_message_destroy(om_msg_p);
    g_list_free_full(addr_l_p, lurch_addr_list_destroy_func);
  }

  free(uname);
  free(db_fn_omemo);
  axc_context_destroy_all(axc_ctx_p);
  free(tempxml);
  omemo_devicelist_destroy(user_dl_p);
}

static void lurch_xml_sent_cb(PurpleConnection * gc_p, xmlnode ** stanza_pp) {
  xmlnode * body_node_p = (void *) 0;
  xmlnode * encrypted_node_p = (void *) 0;
  char * node_name = (*stanza_pp)->name;
  const char * type = xmlnode_get_attrib(*stanza_pp, "type");

  if (uninstall) {
    return;
  }

  if (!g_strcmp0(node_name, "message")) {
    body_node_p = xmlnode_get_child(*stanza_pp, "body");
    if (!body_node_p) {
      return;
    }

    encrypted_node_p = xmlnode_get_child(*stanza_pp, "encrypted");
    if (encrypted_node_p) {
      return;
    }

    if (!g_strcmp0(type, "chat")) {
      lurch_message_encrypt_im(gc_p, stanza_pp);
    } else if (!g_strcmp0(type, "groupchat")) {
      lurch_message_encrypt_groupchat(gc_p, stanza_pp);
    }
  }
}

static void lurch_presence_handle(PurpleConnection * gc_p, xmlnode ** presence_stanza_pp) {
  xmlnode * x_node_p = (void *) 0;
  xmlnode * item_node_p = (void *) 0;

  const char * from = (void *) 0;
  char ** split = (void *) 0;
  char * room_name = (void *) 0;
  char * buddy_nick = (void *) 0;
  const char * jid_full = (void *) 0;
  char * jid = (void *) 0;

  GHashTable * nick_jid_ht_p = (void *) 0;
  int write_to_chat_ht = 0;

  from = xmlnode_get_attrib(*presence_stanza_pp, "from");
  if (!from) {
    goto cleanup;
  }

  x_node_p = xmlnode_get_child_with_namespace(*presence_stanza_pp, "x", "http://jabber.org/protocol/muc#user");
  if (!x_node_p) {
    goto cleanup;
  }

  item_node_p = xmlnode_get_child(x_node_p, "item");
  if (!item_node_p) {
    goto cleanup;
  }

  jid_full = xmlnode_get_attrib(item_node_p, "jid");
  if (!jid_full) {
    goto cleanup;
  }

  jid = jabber_get_bare_jid(jid_full);

  split = g_strsplit(from, "/", 2);
  room_name = split[0];
  buddy_nick = split[1];

  nick_jid_ht_p = g_hash_table_lookup(chat_users_ht_p, room_name);
  if (!nick_jid_ht_p) {
    nick_jid_ht_p = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    write_to_chat_ht = 1;
  }

  (void) g_hash_table_insert(nick_jid_ht_p, g_strdup(buddy_nick), g_strdup(jid));

  if (write_to_chat_ht) {
    (void) g_hash_table_insert(chat_users_ht_p, room_name, nick_jid_ht_p);
  }

cleanup:
  g_strfreev(split);
  free(jid);
}

/**
 * Callback for the "receiving xmlnode" signal.
 * Decrypts message, if applicable.
 */
static void lurch_message_decrypt(PurpleConnection * gc_p, xmlnode ** msg_stanza_pp) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;
  int len;

  omemo_message * msg_p = (void *) 0;
  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t own_id = 0;
  uint8_t * key_p = (void *) 0;
  size_t key_len = 0;
  axc_buf * key_buf_p = (void *) 0;
  axc_buf * key_decrypted_p = (void *) 0;
  char * sender_name = (void *) 0;
  axc_address sender_addr = {0};
  char * bundle_node_name = (void *) 0;
  omemo_message * keytransport_msg_p = (void *) 0;
  char * xml = (void *) 0;
  char * sender = (void *) 0;
  char ** split = (void *) 0;
  char * room_name = (void *) 0;
  char * buddy_nick = (void *) 0;
  GHashTable * nick_jid_ht_p = (void *) 0;
  xmlnode * plaintext_msg_node_p = (void *) 0;
  char * recipient_bare_jid = (void *) 0;
  PurpleConversation * conv_p = (void *) 0;

  const char * type = xmlnode_get_attrib(*msg_stanza_pp, "type");
  const char * from = xmlnode_get_attrib(*msg_stanza_pp, "from");

  if (uninstall) {
    goto cleanup;
  }

  uname = lurch_uname_strip(purple_account_get_username(purple_connection_get_account(gc_p)));
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  if (!g_strcmp0(type, "chat")) {
    sender = jabber_get_bare_jid(from);

    ret_val = omemo_storage_chatlist_exists(sender, db_fn_omemo);
    if (ret_val < 0) {
      err_msg_dbg = g_strdup_printf("failed to look up %s in %s", sender, db_fn_omemo);
      goto cleanup;
    } else if (ret_val == 1) {
      purple_conv_present_error(sender, purple_connection_get_account(gc_p), "Received encrypted message in blacklisted conversation.");
    }
  } else if (!g_strcmp0(type, "groupchat")) {
    split = g_strsplit(from, "/", 2);
    room_name = split[0];
    buddy_nick = split[1];

    ret_val = omemo_storage_chatlist_exists(room_name, db_fn_omemo);
    if (ret_val < 0) {
      err_msg_dbg = g_strdup_printf("failed to look up %s in %s", room_name, db_fn_omemo);
      goto cleanup;
    } else if (ret_val == 0) {
      purple_conv_present_error(room_name, purple_connection_get_account(gc_p), "Received encrypted message in non-OMEMO room.");;
    }

    nick_jid_ht_p = g_hash_table_lookup(chat_users_ht_p, room_name);
    sender = g_strdup(g_hash_table_lookup(nick_jid_ht_p, buddy_nick));
  }

  ret_val = omemo_message_prepare_decryption(xmlnode_to_str(*msg_stanza_pp, &len), &msg_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed import msg for decryption");
    goto cleanup;
  }

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get axc ctx for %s", uname);
    goto cleanup;
  }

  ret_val = axc_get_device_id(axc_ctx_p, &own_id);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get own device id");
    goto cleanup;
  }

  ret_val = omemo_message_get_encrypted_key(msg_p, own_id, &key_p, &key_len);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to get key for own id %i", own_id);
    goto cleanup;
  }
  if (!key_p) {
    purple_debug_info("lurch", "received omemo message that does not contain a key for this device, skipping\n");
    goto cleanup;
  }

  key_buf_p = axc_buf_create(key_p, key_len);
  if (!key_buf_p) {
    err_msg_dbg = g_strdup_printf("failed to create buf for key");
    goto cleanup;
  }

  sender_addr.name = sender;
  sender_addr.name_len = strnlen(sender_addr.name, JABBER_MAX_LEN_BARE);
  sender_addr.device_id = omemo_message_get_sender_id(msg_p);

  ret_val = axc_pre_key_message_process(key_buf_p, &sender_addr, axc_ctx_p, &key_decrypted_p);
  if (ret_val == AXC_ERR_NOT_A_PREKEY_MSG) {
    if (axc_session_exists_initiated(&sender_addr, axc_ctx_p)) {
      ret_val = axc_message_decrypt_from_serialized(key_buf_p, &sender_addr, axc_ctx_p, &key_decrypted_p);
      if (ret_val) {
        err_msg_dbg = g_strdup_printf("failed to decrypt key");
        goto cleanup;
      }
    } else {
      purple_debug_info("lurch", "received omemo message that does not contain a key for this device, ignoring\n");
      goto cleanup;
    }
  } else if (ret_val == AXC_ERR_INVALID_KEY_ID) {
    ret_val = omemo_bundle_get_pep_node_name(sender_addr.device_id, &bundle_node_name);
    if (ret_val) {
      err_msg_dbg = g_strdup_printf("failed to get bundle pep node name");
      goto cleanup;
    }

    jabber_pep_request_item(purple_connection_get_protocol_data(gc_p),
                            sender_addr.name, bundle_node_name,
                            (void *) 0,
                            lurch_pep_bundle_for_keytransport);

  } else if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to prekey msg");
    goto cleanup;
  } else {
    lurch_bundle_publish_own(purple_connection_get_protocol_data(gc_p));
  }

  if (!omemo_message_has_payload(msg_p)) {
    purple_debug_info("lurch", "received keytransportmsg\n");
    goto cleanup;
  }

  ret_val = omemo_message_export_decrypted(msg_p, axc_buf_get_data(key_decrypted_p), axc_buf_get_len(key_decrypted_p), &crypto, &xml);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to decrypt payload");
    goto cleanup;
  }

  plaintext_msg_node_p = xmlnode_from_str(xml, -1);

  if (g_strcmp0(sender, uname)) {
    *msg_stanza_pp = plaintext_msg_node_p;
  } else {
    if (!g_strcmp0(type, "chat")) {
      recipient_bare_jid = jabber_get_bare_jid(xmlnode_get_attrib(*msg_stanza_pp, "to"));
      conv_p = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, sender, purple_connection_get_account(gc_p));
      if (!conv_p) {
        conv_p = purple_conversation_new(PURPLE_CONV_TYPE_IM, purple_connection_get_account(gc_p), recipient_bare_jid);;
      }
      purple_conversation_write(conv_p, uname, xmlnode_get_data(xmlnode_get_child(plaintext_msg_node_p, "body")), PURPLE_MESSAGE_SEND, time((void *) 0));
      *msg_stanza_pp = (void *) 0;
    }
  }

cleanup:
  if (err_msg_dbg) {
    purple_conv_present_error(sender, purple_connection_get_account(gc_p), LURCH_ERR_STRING_DECRYPT);
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    free(err_msg_dbg);
  }

  g_strfreev(split);
  free(sender);
  free(xml);
  free(bundle_node_name);
  free(sender_name);
  axc_buf_free(key_decrypted_p);
  axc_buf_free(key_buf_p);
  free(key_p);
  axc_context_destroy_all(axc_ctx_p);
  free(uname);
  free(db_fn_omemo);
  free(recipient_bare_jid);
  omemo_message_destroy(keytransport_msg_p);
  omemo_message_destroy(msg_p);
}

static void lurch_message_warn(PurpleConnection * gc_p, xmlnode ** msg_stanza_pp) {
  int ret_val = 0;

  xmlnode * temp_node_p = (void *) 0;
  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  char * conv_name = (void *) 0;
  char ** split = (void *) 0;
  char * room_name = (void *) 0;

  const char * type = xmlnode_get_attrib(*msg_stanza_pp, "type");
  const char * from = xmlnode_get_attrib(*msg_stanza_pp, "from");

  uname = lurch_uname_strip(purple_account_get_username(purple_connection_get_account(gc_p)));
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    goto cleanup;
  }

  temp_node_p = xmlnode_get_child(*msg_stanza_pp, "body");
  if (!temp_node_p) {
    goto cleanup;
  }

  if (!g_strcmp0(type, "chat")) {
    conv_name = jabber_get_bare_jid(from);

    ret_val = axc_session_exists_any(conv_name, axc_ctx_p);
    if (ret_val < 0) {
      goto cleanup;
    } else if (ret_val == 0) {
      goto cleanup;
    } else if (ret_val == 1) {
      ret_val = omemo_storage_chatlist_exists(conv_name, db_fn_omemo);
      if (ret_val == 0) {
        purple_conv_present_error(conv_name, purple_connection_get_account(gc_p),
                                  "Even though you have an encryption session with this user, you received a plaintext message.");
      }
    } else {
    }
  } else if (!g_strcmp0(type, "groupchat")) {
    split = g_strsplit(from, "/", 2);
    room_name = split[0];

    ret_val = omemo_storage_chatlist_exists(room_name, db_fn_omemo);
    if (ret_val < 0) {
      goto cleanup;
    } else if (ret_val == 0) {
      goto cleanup;
    } else if (ret_val == 1) {
      purple_conv_present_error(room_name, purple_connection_get_account(gc_p),
                                "This groupchat is set to encrypted, but you received a plaintext message.");
    }
  }

cleanup:
  free(uname);
  free(db_fn_omemo);
  free(conv_name);
  g_strfreev(split);
  axc_context_destroy_all(axc_ctx_p);
}

static void lurch_xml_received_cb(PurpleConnection * gc_p, xmlnode ** stanza_pp) {
  char * node_name = (*stanza_pp)->name;
  xmlnode * temp_node_p = (void *) 0;

  if (uninstall) {
    return;
  }

  if (!g_strcmp0(node_name, "presence")) {
    lurch_presence_handle(gc_p, stanza_pp);
  } else if (!g_strcmp0(node_name, "message")) {
    temp_node_p = xmlnode_get_child(*stanza_pp, "encrypted");
    if (temp_node_p) {
      lurch_message_decrypt(gc_p, stanza_pp);
    } else {
      lurch_message_warn(gc_p, stanza_pp);
    }
  }
}

static int lurch_topic_update_im(PurpleConversation * conv_p) {
  int ret_val = 0;

  char * uname = (void *) 0;
  const char * partner_name = purple_conversation_get_name(conv_p);
  char * partner_name_bare = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  omemo_devicelist * dl_p = (void *) 0;

  char * new_title = (void *) 0;

  uname = lurch_uname_strip(purple_account_get_username(purple_conversation_get_account(conv_p)));
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);
  partner_name_bare = jabber_get_bare_jid(partner_name);

  if (uninstall) {
    goto cleanup;
  }

  ret_val = omemo_storage_chatlist_exists(partner_name_bare, db_fn_omemo);
  if (ret_val < 0 || ret_val > 0) {
    goto cleanup;
  }

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    goto cleanup;
  }

  ret_val = axc_session_exists_any(partner_name_bare, axc_ctx_p);
  if (ret_val < 0) {
    goto cleanup;
  } else if (ret_val) {
    new_title = g_strdup_printf("%s (%s)", partner_name, "OMEMO");

  } else {
    ret_val = omemo_storage_user_devicelist_retrieve(partner_name_bare, db_fn_omemo, &dl_p);
    if (ret_val) {
      goto cleanup;
    }

    if (!omemo_devicelist_is_empty(dl_p)) {
      new_title = g_strdup_printf("%s (%s)", partner_name, "OMEMO available");
    }
  }

  if (new_title) {
    purple_conversation_set_title(conv_p, new_title);
  }

cleanup:
  free(uname);
  free(new_title);
  axc_context_destroy_all(axc_ctx_p);
  free(db_fn_omemo);
  omemo_devicelist_destroy(dl_p);
  free(partner_name_bare);

  return ret_val;
}

static int lurch_topic_update_chat(PurpleConversation * conv_p) {
  int ret_val = 0;

  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  char * new_title = (void *) 0;

  uname = lurch_uname_strip(purple_account_get_username(purple_conversation_get_account(conv_p)));
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  if (uninstall) {
    goto cleanup;
  }

  ret_val = omemo_storage_chatlist_exists(purple_conversation_get_name(conv_p), db_fn_omemo);
  if (ret_val < 1) {
    goto cleanup;
  }

  new_title = g_strdup_printf("%s (%s)", purple_conversation_get_title(conv_p), "OMEMO");
  purple_conversation_set_title(conv_p, new_title);

cleanup:
  free(uname);
  free(db_fn_omemo);
  free(new_title);

  return ret_val;
}

static void lurch_conv_created_cb(PurpleConversation * conv_p) {
  if (strncmp(purple_account_get_protocol_id(purple_conversation_get_account(conv_p)), JABBER_PROTOCOL_ID, strlen(JABBER_PROTOCOL_ID))) {
    return;
  }

  if (purple_conversation_get_type(conv_p) == 1) {
    lurch_topic_update_im(conv_p);
  } else if (purple_conversation_get_type(conv_p) == 2) {
    lurch_topic_update_chat(conv_p);
  }
}

static void lurch_conv_updated_cb(PurpleConversation * conv_p, PurpleConvUpdateType type) {
  if (strncmp(purple_account_get_protocol_id(purple_conversation_get_account(conv_p)), JABBER_PROTOCOL_ID, strlen(JABBER_PROTOCOL_ID))) {
    return;
  }

  if (type == 11) {
    if (!topic_changed) {
      topic_changed = 1;
      if (purple_conversation_get_type(conv_p) == 1) {
        lurch_topic_update_im(conv_p);
      } else if (purple_conversation_get_type(conv_p) == 2) {
        lurch_topic_update_chat(conv_p);
      }

    } else {
      topic_changed = 0;
    }
  }
}

/**
 * Creates a fingerprint which resembles the one displayed by Conversations etc.
 * Also useful for avoiding the smileys produced by ':d'...
 *
 * @param fp The fingerprint string as returned by purple_base16_encode_chunked
 * @return A newly allocated string which contains the fingerprint in printable format, or NULL.
 */
static char * lurch_fp_printable(const char * fp) {
  char ** split = (void *) 0;
  char * temp1 = (void *) 0;
  char * temp2 = (void *) 0;

  if (!fp) {
    return (void *) 0;
  }

  split = g_strsplit(fp, ":", 0);
  temp2 = g_strdup("");

  for (int i = 1; i <= 32; i += 4) {
    temp1 = g_strconcat(temp2, split[i], split[i+1], split[i+2], split[i+3], " ", NULL);
    g_free(temp2);
    temp2 = g_strdup(temp1);
    g_free(temp1);
  }

  g_strfreev(split);
  return temp2;
}

static PurpleCmdRet lurch_cmd_func(PurpleConversation * conv_p,
                                   const gchar * cmd,
                                   gchar ** args,
                                   gchar ** error,
                                   void * data_p) {
  int ret_val = 0;
  char * err_msg = (void *) 0;

  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t id = 0;
  uint32_t remove_id = 0;
  axc_buf * key_buf_p = (void *) 0;
  gchar * fp = (void *) 0;
  char * fp_printable = (void *) 0;
  omemo_devicelist * own_dl_p = (void *) 0;
  omemo_devicelist * other_dl_p = (void *) 0;
  GList * own_l_p = (void *) 0;
  GList * other_l_p = (void *) 0;
  GList * curr_p = (void *) 0;
  char * temp_msg_1 = (void *) 0;
  char * temp_msg_2 = (void *) 0;
  char * temp_msg_3 = (void *) 0;
  xmlnode * dl_node_p = (void *) 0;
  char * bare_jid = (void *) 0;

  char * msg = (void *) 0;

  uname = lurch_uname_strip(purple_account_get_username(purple_conversation_get_account(conv_p)));
  db_fn_omemo = lurch_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = lurch_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    err_msg = g_strdup("Failed to create axc ctx.");
    goto cleanup;
  }

  ret_val = axc_get_device_id(axc_ctx_p, &id);
  if (ret_val) {
    err_msg = g_strdup_printf("Failed to access axc db %s. Does the path seem correct?", axc_context_get_db_fn(axc_ctx_p));
    goto cleanup;
  }

  if (!g_strcmp0(args[0], "uninstall")) {
    if (!g_strcmp0(args[1], "yes")) {
      ret_val = omemo_devicelist_get_pep_node_name(&temp_msg_1);
      if (ret_val) {
        err_msg = g_strdup("Failed to get devicelist PEP node name.");
        goto cleanup;
      }

      ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &own_dl_p);
      if (ret_val) {
        err_msg = g_strdup_printf("Failed to access omemo db %s. Does the path seem correct?", db_fn_omemo);
        goto cleanup;
      }

      ret_val = axc_get_device_id(axc_ctx_p, &remove_id);
      if (ret_val) {
        err_msg = g_strdup_printf("Failed to get own ID from DB %s.", axc_context_get_db_fn(axc_ctx_p));
        goto cleanup;
      }

      ret_val = omemo_devicelist_remove(own_dl_p, remove_id);
      if (ret_val) {
        err_msg = g_strdup_printf("Failed to remove %i from the list in DB %s.", remove_id, db_fn_omemo);
        goto cleanup;
      }

      ret_val = omemo_devicelist_export(own_dl_p, &temp_msg_1);
      if (ret_val) {
        err_msg = g_strdup("Failed to export new devicelist to xml string.");
        goto cleanup;
      }

      uninstall = 1;
      purple_account_set_bool(purple_conversation_get_account(conv_p), LURCH_ACC_SETTING_INITIALIZED, FALSE);
      dl_node_p = xmlnode_from_str(temp_msg_1, -1);
      jabber_pep_publish(purple_connection_get_protocol_data(purple_conversation_get_gc(conv_p)), dl_node_p);
      msg = g_strdup_printf("Published devicelist minus this device's ID. "
                            "You can deactivate the plugin now, otherwise it will be republished at the next startup. "
                            "To delete all existing data you also have to delete the DB files in your ~/.pidgin folder.");
    } else {
      msg = g_strdup("To uninstall lurch for this device, type 'lurch uninstall yes'.");
    }
  } else if (!g_strcmp0(args[0], "help")) {
    msg = g_strdup("The following commands exist to interact with the lurch plugin:\n\n"
                   "In conversations with one user:\n"
                   " - '/lurch blacklist add': Adds conversation partner to blacklist.\n"
                   " - '/lurch blacklist remove': Removes conversation partner from blacklist.\n"
                   " - '/lurch show id own': Displays this device's ID.\n"
                   " - '/lurch show id list': Displays this account's devicelist.\n"
                   " - '/lurch show fp own': Displays this device's key fingerprint.\n"
                   " - '/lurch show fp conv': Displays the fingerprints of all participating devices.\n"
                   " - '/lurch remove id <id>': Removes a device ID from the own devicelist.\n"
                   "\n"
                   "In conversations with multiple users:\n"
                   " - '/lurch enable': Enables OMEMO encryption for the conversation.\n"
                   " - '/lurch disable': Disables OMEMO encryption for the conversation.\n"
                   "\n"
                   "In all types of conversations:\n"
                   " - '/lurch help': Displays this message.\n"
                   " - '/lurch uninstall': Uninstalls this device from OMEMO by removing its device ID from the devicelist.");
  } else {
    if(purple_conversation_get_type(conv_p) == 1) {
      if (!g_strcmp0(args[0], "blacklist")) {
        if (!g_strcmp0(args[1], "add")) {
          temp_msg_1 = jabber_get_bare_jid(purple_conversation_get_name(conv_p));
          ret_val = omemo_storage_chatlist_save(temp_msg_1, db_fn_omemo);
          if (ret_val) {
            err_msg = g_strdup_printf("Failed to look up %s in DB %s.", temp_msg_1, db_fn_omemo);
            goto cleanup;
          }

          purple_conversation_autoset_title(conv_p);

          msg = g_strdup_printf("Added %s to your blacklist. Even if OMEMO is available, it will not be used.", temp_msg_1);
        } else if (!g_strcmp0(args[1], "remove")) {
          temp_msg_1 = jabber_get_bare_jid(purple_conversation_get_name(conv_p));
          ret_val = omemo_storage_chatlist_delete(temp_msg_1, db_fn_omemo);
          if (ret_val) {
            err_msg = g_strdup_printf("Failed to delete %s in DB %s.", temp_msg_1, db_fn_omemo);
            goto cleanup;
          }

          msg = g_strdup_printf("Removed %s from your blacklist. If OMEMO is available, it will be used.", temp_msg_1);

          topic_changed = 1;
          lurch_topic_update_im(conv_p);
        } else {
          msg = g_strdup("Valid arguments for 'lurch blacklist' are 'add' and 'remove'.");
        }
      } else if (!g_strcmp0(args[0], "show")) {
        if (!g_strcmp0(args[1], "id")) {
          if (!g_strcmp0(args[2], "own")) {
            msg = g_strdup_printf("Your own device ID is %i.", id);
          } else if (!g_strcmp0(args[2], "list")) {
            ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &own_dl_p);
            if (ret_val) {
              err_msg = g_strdup_printf("Failed to access omemo db %s.", db_fn_omemo);
              goto cleanup;
            }

            temp_msg_1 = g_strdup_printf("This user (%s) has the following devices:\n"
                                         "%i (this device)\n", uname, id);

            own_l_p = omemo_devicelist_get_id_list(own_dl_p);
            for (curr_p = own_l_p; curr_p; curr_p = curr_p->next) {
              if (omemo_devicelist_list_data(curr_p) != id) {
                temp_msg_2 = g_strdup_printf("%i\n", omemo_devicelist_list_data(curr_p));
                temp_msg_3 = g_strconcat(temp_msg_1, temp_msg_2, NULL);
                g_free(temp_msg_1);
                temp_msg_1 = temp_msg_3;
                g_free(temp_msg_2);
                temp_msg_2 = (void *) 0;
                temp_msg_3 = (void *) 0;
              }
            }

            msg = g_strdup(temp_msg_1);
          } else {
            msg = g_strdup("Valid arguments for 'lurch show id' are 'own' to display this device's ID "
                           "and 'list' to display this user's device list.");
          }

        } else if (!g_strcmp0(args[1], "fp")) {
          if (!g_strcmp0(args[2], "own")) {
            ret_val = axc_key_load_public_own(axc_ctx_p, &key_buf_p);
            if (ret_val) {
              err_msg = g_strdup_printf("Failed to access axc db %s.", axc_context_get_db_fn(axc_ctx_p));
              goto cleanup;
            }

            fp = purple_base16_encode_chunked(axc_buf_get_data(key_buf_p), axc_buf_get_len(key_buf_p));
            fp_printable = lurch_fp_printable(fp);
            msg = g_strdup_printf("This device's fingerprint is:\n%s\n"
                                  "You should make sure that your conversation partner gets displayed the same for this device.", fp_printable);
          } else if (!g_strcmp0(args[2], "conv")) {

            ret_val = axc_key_load_public_own(axc_ctx_p, &key_buf_p);
            if (ret_val) {
              err_msg = g_strdup_printf("Failed to access axc db %s.", axc_context_get_db_fn(axc_ctx_p));
              goto cleanup;
            }

            fp = purple_base16_encode_chunked(axc_buf_get_data(key_buf_p), axc_buf_get_len(key_buf_p));
            fp_printable = lurch_fp_printable(fp);

            temp_msg_1 = g_strdup_printf("The devices participating in this conversation and their fingerprints are as follows:\n"
                                         "This device's (%s:%i) fingerprint:\n%s\n", uname, id, fp_printable);

            ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &own_dl_p);
            if (ret_val) {
              err_msg = g_strdup_printf("Failed to access omemo db %s.", db_fn_omemo);
              goto cleanup;
            }

            own_l_p = omemo_devicelist_get_id_list(own_dl_p);
            for (curr_p = own_l_p; curr_p; curr_p = curr_p->next) {
              if (omemo_devicelist_list_data(curr_p) != id) {
                ret_val = axc_key_load_public_addr(uname, omemo_devicelist_list_data(curr_p), axc_ctx_p, &key_buf_p);
                if (ret_val < 0) {
                  err_msg = g_strdup_printf("Failed to access axc db %s.", axc_context_get_db_fn(axc_ctx_p));
                  goto cleanup;
                } else if (ret_val == 0) {
                  continue;
                }

                g_free(fp);
                fp = purple_base16_encode_chunked(axc_buf_get_data(key_buf_p), axc_buf_get_len(key_buf_p));
                fp_printable = lurch_fp_printable(fp);
                axc_buf_free(key_buf_p);
                key_buf_p = (void *) 0;

                temp_msg_2 = g_strdup_printf("%s:%i's fingerprint:\n%s\n", uname, omemo_devicelist_list_data(curr_p), fp_printable);
                temp_msg_3 = g_strconcat(temp_msg_1, temp_msg_2, NULL);
                g_free(temp_msg_1);
                temp_msg_1 = temp_msg_3;
                temp_msg_3 = (void *) 0;
                g_free(temp_msg_2);
                temp_msg_2 = (void *) 0;
              }
            }

            bare_jid = jabber_get_bare_jid(purple_conversation_get_name(conv_p));

            ret_val = omemo_storage_user_devicelist_retrieve(bare_jid, db_fn_omemo, &other_dl_p);
            if (ret_val) {
              err_msg = g_strdup_printf("Failed to access omemo db %s.", db_fn_omemo);
              goto cleanup;
            }

            other_l_p = omemo_devicelist_get_id_list(other_dl_p);
            for (curr_p = other_l_p; curr_p; curr_p = curr_p->next) {
              ret_val = axc_key_load_public_addr(bare_jid, omemo_devicelist_list_data(curr_p), axc_ctx_p, &key_buf_p);
              if (ret_val < 0) {
                err_msg = g_strdup_printf("Failed to access axc db %s.", axc_context_get_db_fn(axc_ctx_p));
                goto cleanup;
              } else if (ret_val == 0) {
                continue;
              }

              g_free(fp);
              fp = purple_base16_encode_chunked(axc_buf_get_data(key_buf_p), axc_buf_get_len(key_buf_p));
              fp_printable = lurch_fp_printable(fp);
              axc_buf_free(key_buf_p);
              key_buf_p = (void *) 0;

              temp_msg_2 = g_strdup_printf("%s:%i's fingerprint:\n%s\n", bare_jid, omemo_devicelist_list_data(curr_p), fp_printable);
              temp_msg_3 = g_strconcat(temp_msg_1, temp_msg_2, NULL);
              g_free(temp_msg_1);
              temp_msg_1 = temp_msg_3;
              temp_msg_3 = (void *) 0;
              g_free(temp_msg_2);
              temp_msg_2 = (void *) 0;
            }

            msg = g_strdup(temp_msg_1);

          } else {
            msg = g_strdup("Valid arguments for 'lurch show fp' are 'own' for displaying this device's fingerprint, "
                           "and 'conv' for displaying all devices participating in this conversation and their fingerprints.");
          }
        } else {
          msg = g_strdup("Valid arguments for 'lurch show' are 'id' and 'fp'.");
        }
      } else if (!g_strcmp0(args[0], "remove")) {
        if (!g_strcmp0(args[1], "id")) {
          if (!args[2]) {
            msg = g_strdup("The command 'lurch remove id' must be followed by a device ID.");
          } else {
            ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &own_dl_p);
            if (ret_val) {
              err_msg = g_strdup_printf("Failed to access omemo db %s.", db_fn_omemo);
              goto cleanup;
            }

            remove_id = strtol(args[2], (void *) 0, 10);

            if (!omemo_devicelist_contains_id(own_dl_p, remove_id)) {
              msg = g_strdup_printf("Your devicelist does not contain the ID %s.", args[2]);
            } else {
              ret_val = omemo_devicelist_remove(own_dl_p, remove_id);
              if (ret_val) {
                err_msg = g_strdup_printf("Failed to remove %i from the list.", remove_id);
                goto cleanup;
              }

              ret_val = omemo_devicelist_export(own_dl_p, &temp_msg_1);
              if (ret_val) {
                err_msg = g_strdup("Failed to export new devicelist to xml string.");
                goto cleanup;
              }

              dl_node_p = xmlnode_from_str(temp_msg_1, -1);
              jabber_pep_publish(purple_connection_get_protocol_data(purple_conversation_get_gc(conv_p)), dl_node_p);

              msg = g_strdup_printf("Removed %i from devicelist and republished it.", remove_id);
            }
          }
        } else {
          msg = g_strdup("Valid argument for 'lurch remove' is 'id'.");
        }

      } else {
        msg = g_strdup("Valid arguments for 'lurch' in IMs are 'show', 'remove', 'blacklist', 'uninstall', and 'help'.");
      }
    } else if (purple_conversation_get_type(conv_p) == 2) {
      if (!g_strcmp0(args[0], "enable")) {
        ret_val = omemo_storage_chatlist_save(purple_conversation_get_name(conv_p), db_fn_omemo);
        if (ret_val) {
          err_msg = g_strdup_printf("Failed to look up %s in DB %s.", purple_conversation_get_name(conv_p), db_fn_omemo);
          goto cleanup;
        }

        topic_changed = 1;
        lurch_topic_update_chat(conv_p);

        msg = g_strdup_printf("Activated OMEMO for this chat. This is a client-side setting, so every participant needs to activate it to work.");
      } else if (!g_strcmp0(args[0], "disable")) {
        ret_val = omemo_storage_chatlist_delete(purple_conversation_get_name(conv_p), db_fn_omemo);
        if (ret_val) {
          err_msg = g_strdup_printf("Failed to delete %s in DB %s.\n", purple_conversation_get_name(conv_p), db_fn_omemo);
          goto cleanup;
        }

        msg = g_strdup_printf("Deactivated OMEMO for this chat. "
                              "This is a client-side setting and if other users still have it activated, you will not be able to read their messages.");

        purple_conversation_autoset_title(conv_p);
      } else {
        msg = g_strdup("Valid arguments for 'lurch' in groupchats are 'enable', 'disable', 'uninstall', and 'help'.");
      }
    }
  }

  if (msg) {
    purple_conversation_write(conv_p, "lurch", msg, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time((void *) 0));
  }

cleanup:
  g_free (uname);
  g_free(db_fn_omemo);
  axc_context_destroy_all(axc_ctx_p);
  g_free(msg);
  axc_buf_free(key_buf_p);
  g_free(fp);
  g_free(fp_printable);
  omemo_devicelist_destroy(own_dl_p);
  omemo_devicelist_destroy(other_dl_p);
  g_list_free_full(own_l_p, free);
  g_list_free_full(other_l_p, free);
  g_free(temp_msg_1);
  g_free(temp_msg_2);
  g_free(temp_msg_3);
  g_free(bare_jid);


  if (ret_val < 0) {
    *error = err_msg;
    return PURPLE_CMD_RET_FAILED;
  } else {
    return PURPLE_CMD_RET_OK;
  }
}

/**
 * Actions to perform on plugin load.
 * Inits the crypto and registers signal and PEP handlers.
 */
static gboolean lurch_plugin_load(PurplePlugin * plugin_p) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  char * dl_ns = (void *) 0;
  void * jabber_handle_p = (void *) 0;
  GList * accs_l_p = (void *) 0;
  GList * curr_p = (void *) 0;
  PurpleAccount * acc_p = (void *) 0;

  chat_users_ht_p = g_hash_table_new_full(g_str_hash, g_str_equal, free, (void *) 0);

  omemo_default_crypto_init();

  ret_val = omemo_devicelist_get_pep_node_name(&dl_ns);
  if (ret_val) {
    err_msg_dbg = "failed to get devicelist pep node name";
    goto cleanup;
  }

  lurch_cmd_id = purple_cmd_register("lurch",
                                     "wwws",
                                     PURPLE_CMD_P_PLUGIN,
                                     PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT | PURPLE_CMD_FLAG_PRPL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
                                     JABBER_PROTOCOL_ID,
                                     lurch_cmd_func,
                                     "lurch &lt;help&gt;:  "
                                     "Interface to the lurch plugin. For details, use the 'help' argument.",
                                     (void *) 0);

  // register handlers
  jabber_handle_p = purple_plugins_find_with_id(JABBER_PROTOCOL_ID);

  (void) purple_signal_connect_priority(jabber_handle_p, "jabber-receiving-xmlnode", plugin_p, PURPLE_CALLBACK(lurch_xml_received_cb), NULL, PURPLE_PRIORITY_HIGHEST);
  (void) purple_signal_connect(jabber_handle_p, "jabber-sending-xmlnode", plugin_p, PURPLE_CALLBACK(lurch_xml_sent_cb), NULL);

  jabber_pep_register_handler(dl_ns, lurch_pep_devicelist_event_handler);
  jabber_add_feature(dl_ns, jabber_pep_namespace_only_when_pep_enabled_cb);

  // manually call init code if there are already accounts connected, e.g. when plugin is loaded manually
  accs_l_p = purple_accounts_get_all_active();
  for (curr_p = accs_l_p; curr_p; curr_p = curr_p->next) {
    acc_p = (PurpleAccount *) curr_p->data;
    if (purple_account_is_connected(acc_p)) {
      if (!g_strcmp0(purple_account_get_protocol_id(acc_p), JABBER_PROTOCOL_ID)) {
        lurch_account_connect_cb(acc_p);
      }
    }
  }

  // register install callback
  (void) purple_signal_connect(purple_accounts_get_handle(), "account-signed-on", plugin_p, PURPLE_CALLBACK(lurch_account_connect_cb), NULL);
  (void) purple_signal_connect(purple_conversations_get_handle(), "conversation-created", plugin_p, PURPLE_CALLBACK(lurch_conv_created_cb), NULL);
  (void) purple_signal_connect(purple_conversations_get_handle(), "conversation-updated", plugin_p, PURPLE_CALLBACK(lurch_conv_updated_cb), NULL);

cleanup:
  free(dl_ns);
  if (ret_val) {
    purple_debug_error("lurch", "%s: %s (%i)\n", __func__, err_msg_dbg, ret_val);
    omemo_default_crypto_teardown();
    g_hash_table_destroy(chat_users_ht_p);
    return FALSE;
  }

  return TRUE;
}

static gboolean lurch_plugin_unload(PurplePlugin * plugin_p) {
  //g_hash_table_destroy(chat_users_ht_p);
  omemo_default_crypto_teardown();

  return TRUE;
}

static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,
    PURPLE_MAJOR_VERSION,
    PURPLE_MINOR_VERSION,
    PURPLE_PLUGIN_STANDARD,
    NULL,
    0,
    NULL,
    PURPLE_PRIORITY_DEFAULT,

    "core-riba-lurch",
    "lurch",
    "0.6.1",

    "Implements OMEMO for libpurple.",
    "End-to-end encryption using the Signal protocol, adapted for XMPP.",
    "Richard Bayerle <riba@firemail.cc>",
    "https://github.com/gkdr/lurch",

    lurch_plugin_load,
    lurch_plugin_unload,
    NULL,

    NULL,
    NULL,
    NULL, // plugin config, see libpurple/plugins/pluginpref_example.c
    NULL, // plugin actions, see https://developer.pidgin.im/wiki/CHowTo/PluginActionsHowTo
    NULL,
    NULL,
    NULL,
    NULL
};

static void
lurch_plugin_init(PurplePlugin * plugin_p) {
  PurplePluginInfo * info_p = plugin_p->info;

  info_p->dependencies = g_list_prepend(info_p->dependencies, "prpl-jabber");
}

PURPLE_INIT_PLUGIN(lurch, lurch_plugin_init, info)
