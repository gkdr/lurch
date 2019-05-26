#include <inttypes.h>
#include <glib.h>
#include <purple.h>

#include "pep.h"

#include "axc.h"
#include "libomemo.h"
#include "libomemo_storage.h"

#include "lurch_api.h"
#include "lurch_util.h"

#define MODULE_NAME "lurch-api"

/**
 * Returns a GList of int32_t * containing the devices of the calling account.
 * If the current device is contained in it (which it should be!), it will be first in the list.
 */
static int32_t lurch_api_id_list_get_own(PurpleAccount * acc_p, GList ** list_pp) {
  int32_t ret_val = 0;
  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  omemo_devicelist * dl_p = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t own_id = 0;
  GList * id_list = (void *) 0;
  uint32_t * id_p = (void *) 0;

  uname = lurch_util_uname_strip(purple_account_get_username(acc_p));
  db_fn_omemo = lurch_util_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &dl_p);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to access OMEMO DB %s.", db_fn_omemo);
    goto cleanup;
  }

  ret_val = lurch_util_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to create axc ctx.");
    goto cleanup;
  }

  ret_val = axc_get_device_id(axc_ctx_p, &own_id);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to access axc db %s. Does the path seem correct?", axc_context_get_db_fn(axc_ctx_p));
    goto cleanup;
  }

  if (!omemo_devicelist_contains_id(dl_p, own_id)) {
    purple_debug_warning(MODULE_NAME, "This device's ID is not contained in your devicelist?");
    goto cleanup;
  }

  ret_val = omemo_devicelist_remove(dl_p, own_id);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to remove the ID from the devicelist.");
    goto cleanup;
  }

  id_list = omemo_devicelist_get_id_list(dl_p);

  id_p = g_malloc(sizeof(uint32_t));
  if (!id_p) {
    ret_val = LURCH_ERR_NOMEM;
    goto cleanup;
  }
  *id_p = own_id;

  id_list = g_list_prepend(id_list, id_p);

cleanup:
  if (!ret_val) {
    *list_pp = id_list;
  }

  g_free(uname);
  g_free(db_fn_omemo);
  omemo_devicelist_destroy(dl_p);
  axc_context_destroy_all(axc_ctx_p);

  return ret_val;
}

void lurch_api_id_list_handler(PurpleAccount * acc_p, void (*cb)(int32_t err, GList * id_list, void * user_data_p), void * user_data_p) {
  int32_t ret_val = 0;
  GList * id_list = (void *) 0;

  ret_val = lurch_api_id_list_get_own(acc_p, &id_list);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to get the own, sorted ID list.");
    goto cleanup;
  }

cleanup:
  cb(ret_val, id_list, user_data_p);

  g_list_free_full(id_list, free);
}

void lurch_api_id_remove_handler(PurpleAccount * acc_p, uint32_t device_id, void (*cb)(int32_t err, void * user_data_p), void * user_data_p) {
  int32_t ret_val = 0;
  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  omemo_devicelist * dl_p = (void *) 0;
  char * exported_devicelist = (void *) 0;
  xmlnode * publish_node_p = (void *) 0;

  uname = lurch_util_uname_strip(purple_account_get_username(acc_p));
  db_fn_omemo = lurch_util_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &dl_p);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to access the OMEMO DB %s to retrieve the devicelist.", db_fn_omemo);
    goto cleanup;
  }

  if (!omemo_devicelist_contains_id(dl_p, device_id)) {
    ret_val = LURCH_ERR_DEVICE_NOT_IN_LIST;
    purple_debug_error(MODULE_NAME, "Your devicelist does not contain the device ID %i.", device_id);
    goto cleanup;
  }

  ret_val = omemo_devicelist_remove(dl_p, device_id);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to remove the device ID %i from %s's devicelist.", device_id, uname);
    goto cleanup;
  }

  ret_val = omemo_devicelist_export(dl_p, &exported_devicelist);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to export new devicelist without device ID %i.", device_id);
    goto cleanup;
  }

  publish_node_p = xmlnode_from_str(exported_devicelist, -1);
  jabber_pep_publish(purple_connection_get_protocol_data(purple_account_get_connection(acc_p)), publish_node_p);
  // publish_node_p will be freed by the jabber prpl

cleanup:
  cb(ret_val, user_data_p);

  g_free(uname);
  g_free(db_fn_omemo);
  omemo_devicelist_destroy(dl_p);
  g_free(exported_devicelist);
}

void lurch_api_enable_im_handler(PurpleAccount * acc_p, const char * contact_bare_jid, void (*cb)(int32_t err, void * user_data_p), void * user_data_p) {
  int32_t ret_val = 0;
  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;

  uname = lurch_util_uname_strip(purple_account_get_username(acc_p));
  db_fn_omemo = lurch_util_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = omemo_storage_chatlist_delete(contact_bare_jid, db_fn_omemo);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to delete %s from the blacklist in OMEMO DB %s.", contact_bare_jid, db_fn_omemo);
  }

  cb(ret_val, user_data_p);

  g_free(uname);
  g_free(db_fn_omemo);
}

void lurch_api_disable_im_handler(PurpleAccount * acc_p, const char * contact_bare_jid, void (*cb)(int32_t err, void * user_data_p), void * user_data_p) {
  int32_t ret_val = 0;
  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;

  uname = lurch_util_uname_strip(purple_account_get_username(acc_p));
  db_fn_omemo = lurch_util_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = omemo_storage_chatlist_save(contact_bare_jid, db_fn_omemo);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to add %s to the blacklist in OMEMO DB %s.", contact_bare_jid, db_fn_omemo);
  }

  cb(ret_val, user_data_p);

  g_free(uname);
  g_free(db_fn_omemo);
}

void lurch_api_fp_get_handler(PurpleAccount * acc_p, void (*cb)(int32_t err, const char * fp_printable, void * user_data_p), void * user_data_p) {
  int32_t ret_val = 0;
  char * uname = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  axc_buf * key_buf_p = (void *) 0;
  gchar * fp = (void *) 0;
  char * fp_printable = (void *) 0;

  uname = lurch_util_uname_strip(purple_account_get_username(acc_p));

  ret_val = lurch_util_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to create axc ctx.\n");
    goto cleanup;
  }

  ret_val = axc_key_load_public_own(axc_ctx_p, &key_buf_p);
  if (ret_val) {
    purple_debug_error("Failed to load public key from axc db %s.", axc_context_get_db_fn(axc_ctx_p));
    goto cleanup;
  }

  fp = purple_base16_encode_chunked(axc_buf_get_data(key_buf_p), axc_buf_get_len(key_buf_p));
  fp_printable = lurch_util_fp_get_printable(fp);

cleanup:
  cb(ret_val, fp_printable, user_data_p);

  g_free(fp_printable);
  g_free(fp);
  axc_buf_free(key_buf_p);
  axc_context_destroy_all(axc_ctx_p);
}

/**
 * Given a list of IDs, retrieves the public keys from the libsignal sessions and creates hash table with ID to fingerprint pairs.
 * If there is an entry in the devicelist, but no session yet, the fingerprint cannot be retrieved this way and the value will be NULL.
 * g_hash_table_destroy() the table when done with it.
 */
static int32_t lurch_api_fp_create_table(const char * jid,  axc_context * axc_ctx_p, const GList * id_list, GHashTable ** id_fp_table_pp) {
  int32_t ret_val = 0;
  GHashTable * id_fp_table = (void *) 0;
  const GList * curr_p = (void *) 0;
  uint32_t curr_device_id = 0;
  axc_buf * key_buf_p = (void *) 0;
  gchar * fp = (void *) 0;

  id_fp_table = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, g_free);

  for (curr_p = id_list; curr_p; curr_p = curr_p->next) {
    curr_device_id = omemo_devicelist_list_data(curr_p);

    ret_val = axc_key_load_public_addr(jid, curr_device_id, axc_ctx_p, &key_buf_p);
    if (ret_val < 0) {
      purple_debug_error(MODULE_NAME, "Failed to load key for %s:%i", jid, curr_device_id);
      goto cleanup;
    } else if (ret_val == 0) {
      purple_debug_warning(MODULE_NAME, "Tried to load public key for %s:%i, but no session exists", jid, curr_device_id);
      (void) g_hash_table_insert(id_fp_table, curr_p->data, NULL);
      continue;
    }

    fp = purple_base16_encode_chunked(axc_buf_get_data(key_buf_p), axc_buf_get_len(key_buf_p));
    (void) g_hash_table_insert(id_fp_table, curr_p->data, lurch_util_fp_get_printable(fp));

    axc_buf_free(key_buf_p);
    key_buf_p = (void *) 0;
    g_free(fp);
    fp = (void *) 0;

    ret_val = 0;
  }

cleanup:
  if (ret_val) {
    g_hash_table_destroy(id_fp_table);
  } else {
    *id_fp_table_pp = id_fp_table;
  }

  return ret_val;
}

// returns NULL as hash table if devicelist is empty
void lurch_api_fp_list_handler(PurpleAccount * acc_p, void (*cb)(int32_t err, GHashTable * id_fp_table, void * user_data_p), void * user_data_p) {
  int32_t ret_val = 0;
  GList * own_id_list = (void *) 0;
  char * uname = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  GHashTable * id_fp_table = (void *) 0;
  axc_buf * key_buf_p = (void *) 0;
  gchar * fp = (void *) 0;

  ret_val = lurch_api_id_list_get_own(acc_p, &own_id_list);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to get the own, sorted ID list.");
    goto cleanup;
  }

  if (g_list_length(own_id_list) == 0) {
    goto cleanup;
  }

  uname = lurch_util_uname_strip(purple_account_get_username(acc_p));
  ret_val = lurch_util_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to create axc ctx for %s.", uname);
    goto cleanup;
  }

  ret_val = lurch_api_fp_create_table(uname, axc_ctx_p, own_id_list->next, &id_fp_table);
  if (ret_val) {
    goto cleanup;
  }

  ret_val = axc_key_load_public_own(axc_ctx_p, &key_buf_p);
  if (ret_val) {
    purple_debug_error("Failed to load public key from axc db %s.", axc_context_get_db_fn(axc_ctx_p));
    goto cleanup;
  }

  fp = purple_base16_encode_chunked(axc_buf_get_data(key_buf_p), axc_buf_get_len(key_buf_p));
  (void) g_hash_table_insert(id_fp_table, own_id_list->data, lurch_util_fp_get_printable(fp));
  g_free(fp);
  fp = (void *) 0;

cleanup:
  cb(ret_val, id_fp_table, user_data_p);

  g_list_free_full(own_id_list, g_free);
  g_free(uname);
  axc_context_destroy_all(axc_ctx_p);
  g_hash_table_destroy(id_fp_table);
  axc_buf_free(key_buf_p);
  g_free(fp);
}

// returns NULL as hash table if devicelist is empty
void lurch_api_fp_other_handler(PurpleAccount * acc_p, const char * contact_bare_jid, void (*cb)(int32_t err, GHashTable * id_fp_table, void * user_data_p), void * user_data_p) {
  int32_t ret_val = 0;
  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  omemo_devicelist * dl_p = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  GHashTable * id_fp_table = (void *) 0;
  GList * id_list = (void *) 0;
  axc_buf * key_buf_p = (void *) 0;

  uname = lurch_util_uname_strip(purple_account_get_username(acc_p));
  db_fn_omemo = lurch_util_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = omemo_storage_user_devicelist_retrieve(contact_bare_jid, db_fn_omemo, &dl_p);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to access OMEMO DB %s.", db_fn_omemo);
    goto cleanup;
  }

  if (omemo_devicelist_is_empty(dl_p)) {
    goto cleanup;
  }

  ret_val = lurch_util_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to create axc ctx for %s.", uname);
    goto cleanup;
  }

  id_list = omemo_devicelist_get_id_list(dl_p);

  ret_val = lurch_api_fp_create_table(contact_bare_jid, axc_ctx_p, id_list, &id_fp_table);

cleanup:
  cb(ret_val, id_fp_table, user_data_p);

  g_free(uname);
  g_free(db_fn_omemo);
  omemo_devicelist_destroy(dl_p);
  axc_context_destroy_all(axc_ctx_p);
  g_hash_table_destroy(id_fp_table);
  g_list_free_full(id_list, free);
  axc_buf_free(key_buf_p);
}

void lurch_api_status_im_handler(PurpleAccount * acc_p, const char * contact_bare_jid, void (*cb)(int32_t err, lurch_status_t status, void * user_data_p), void * user_data_p) {
  int32_t ret_val = 0;
  lurch_status_t status = LURCH_STATUS_DISABLED;

  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  omemo_devicelist * dl_p = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;

  uname = lurch_util_uname_strip(purple_account_get_username(acc_p));
  db_fn_omemo = lurch_util_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = omemo_storage_chatlist_exists(contact_bare_jid, db_fn_omemo);
  if (ret_val < 0 || ret_val > 1) {
    purple_debug_error(MODULE_NAME, "Failed to look up %s in file %s.", contact_bare_jid, db_fn_omemo);
    goto cleanup;
  } else if (ret_val == 0) {
    // conversation is not on blacklist, continue
  } else if (ret_val == 1) {
    ret_val = 0;
    status = LURCH_STATUS_DISABLED;
    goto cleanup;
  }

  ret_val = omemo_storage_user_devicelist_retrieve(contact_bare_jid, db_fn_omemo, &dl_p);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to get the devicelist for %s from %s.", contact_bare_jid, db_fn_omemo);
    goto cleanup;
  }

  if (omemo_devicelist_is_empty(dl_p)) {
    ret_val = 0;
    status = LURCH_STATUS_NOT_SUPPORTED;
    goto cleanup;
  }

  ret_val = lurch_util_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to create axc ctx for %s.", uname);
    goto cleanup;
  }

  ret_val = axc_session_exists_any(contact_bare_jid, axc_ctx_p);
  if (ret_val < 0) {
    purple_debug_error(MODULE_NAME, "Failed to look up session with %s.", contact_bare_jid);
    goto cleanup;
  } else if (ret_val == 0) {
    ret_val = 0;
    status = LURCH_STATUS_NO_SESSION;
  } else {
    ret_val = 0;
    status = LURCH_STATUS_OK;
  }

cleanup:
  cb(ret_val, status, user_data_p);

  g_free(uname);
  g_free(db_fn_omemo);
  omemo_devicelist_destroy(dl_p);
  axc_context_destroy_all(axc_ctx_p);
}

static void lurch_api_marshal_VOID__POINTER_INT_POINTER_POINTER(PurpleCallback cb, va_list args, void * data, void ** return_val) {
	void * arg1 = va_arg(args, void *);
	gint32 arg2 = va_arg(args, guint);
  void * arg3 = va_arg(args, void *);
  void * arg4 = va_arg(args, void *);

	((void (*)(void *, guint, void *, void *, void *))cb)(arg1, arg2, arg3, arg4, data);
}


typedef enum {
  LURCH_API_HANDLER_ACC_CB_DATA = 0,
  LURCH_API_HANDLER_ACC_JID_CB_DATA,
  LURCH_API_HANDLER_ACC_DID_CB_DATA
} lurch_api_handler_t;

/**
 * When adding a new signal: increase this number and add the name, handler function, and handler function type
 * to the respective array.
 */
#define NUM_OF_SIGNALS 8

const char * signal_names[NUM_OF_SIGNALS] = {
  "lurch-id-list",
  "lurch-id-remove",
  "lurch-enable-im",
  "lurch-disable-im",
  "lurch-fp-get",
  "lurch-fp-list",
  "lurch-fp-other",
  "lurch-status-im"
};

const void * signal_handlers[NUM_OF_SIGNALS] = {
  lurch_api_id_list_handler,
  lurch_api_id_remove_handler,
  lurch_api_enable_im_handler,
  lurch_api_disable_im_handler,
  lurch_api_fp_get_handler,
  lurch_api_fp_list_handler,
  lurch_api_fp_other_handler,
  lurch_api_status_im_handler
};

const lurch_api_handler_t signal_handler_types[NUM_OF_SIGNALS] = {
  LURCH_API_HANDLER_ACC_CB_DATA,
  LURCH_API_HANDLER_ACC_DID_CB_DATA,
  LURCH_API_HANDLER_ACC_JID_CB_DATA,
  LURCH_API_HANDLER_ACC_JID_CB_DATA,
  LURCH_API_HANDLER_ACC_CB_DATA,
  LURCH_API_HANDLER_ACC_CB_DATA,
  LURCH_API_HANDLER_ACC_JID_CB_DATA,
  LURCH_API_HANDLER_ACC_JID_CB_DATA
};

void lurch_api_init() {
  void * plugins_handle_p = purple_plugins_get_handle();

  for (int i = 0; i < NUM_OF_SIGNALS; i++) {
    const char * signal_name = signal_names[i];

    switch (signal_handler_types[i]) {
      case LURCH_API_HANDLER_ACC_CB_DATA:
        purple_signal_register(
          plugins_handle_p,
          signal_name,
          purple_marshal_VOID__POINTER_POINTER_POINTER,
          NULL,
          3,
          purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_ACCOUNT),
          purple_value_new(PURPLE_TYPE_POINTER),
          purple_value_new(PURPLE_TYPE_POINTER)
        );
        break;
      case LURCH_API_HANDLER_ACC_JID_CB_DATA:
        purple_signal_register(
          plugins_handle_p,
          signal_name,
          purple_marshal_VOID__POINTER_POINTER_POINTER_POINTER,
          NULL,
          4,
          purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_ACCOUNT),
          purple_value_new(PURPLE_TYPE_STRING),
          purple_value_new(PURPLE_TYPE_POINTER),
          purple_value_new(PURPLE_TYPE_POINTER)
        );
        break;
      case LURCH_API_HANDLER_ACC_DID_CB_DATA:
        purple_signal_register(
          plugins_handle_p,
          signal_name,
          lurch_api_marshal_VOID__POINTER_INT_POINTER_POINTER,
          NULL,
          4,
          purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_ACCOUNT),
          purple_value_new(PURPLE_TYPE_INT),
          purple_value_new(PURPLE_TYPE_POINTER),
          purple_value_new(PURPLE_TYPE_POINTER)
        );
        break;
      default:
        purple_debug_fatal(MODULE_NAME, "Unknown handler function type, aborting initialization.");
    }

    purple_signal_connect(
      plugins_handle_p,
      signal_name,
      MODULE_NAME,
      PURPLE_CALLBACK(signal_handlers[i]),
      NULL
    );
  }
}

void lurch_api_unload() {
  void * plugins_handle_p = purple_plugins_get_handle();

  for (int i = 0; i < NUM_OF_SIGNALS; i++) {
    const char * signal_name = signal_names[i];

    purple_signal_disconnect(
      plugins_handle_p,
      signal_name,
      MODULE_NAME,
      PURPLE_CALLBACK(signal_handlers[i])
    );

    purple_signal_unregister(plugins_handle_p, signal_name);
  }
}