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

void lurch_api_id_show_handler(PurpleAccount * acc_p, void (*cb)(int32_t err, uint32_t id, void * user_data_p), void * user_data_p) {
  int32_t ret_val = 0;
  char * uname = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t id = 0;

  uname = lurch_util_uname_strip(purple_account_get_username(acc_p));
  
  ret_val = lurch_util_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to create axc ctx.\n");
    goto cleanup;
  }

  ret_val = axc_get_device_id(axc_ctx_p, &id);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to access axc db %s. Does the path seem correct?", axc_context_get_db_fn(axc_ctx_p));
    goto cleanup;
  }

cleanup:
  cb(ret_val, id, user_data_p);

  axc_context_destroy_all(axc_ctx_p);
  g_free(uname);
}

void lurch_api_id_list_handler(PurpleAccount * acc_p, void (*cb)(int32_t err, GList * id_list, void * user_data_p), void * user_data_p) {
  int32_t ret_val = 0;
  char * uname = (void *) 0;
  char * db_fn_omemo = (void *) 0;
  omemo_devicelist * dl_p = (void *) 0;
  GList * id_list = (void *) 0;

  uname = lurch_util_uname_strip(purple_account_get_username(acc_p));
  db_fn_omemo = lurch_util_uname_get_db_fn(uname, LURCH_DB_NAME_OMEMO);

  ret_val = omemo_storage_user_devicelist_retrieve(uname, db_fn_omemo, &dl_p);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to access OMEMO DB %s.", db_fn_omemo);
  }

  id_list = omemo_devicelist_get_id_list(dl_p);

  //TODO: somehow make clear which is the own ID, maybe sort the list so that the own ID is always the first?
  //TODO: then probably merge this with "id show", no one needs two of those

  cb(ret_val, id_list, user_data_p);

  g_free(uname);
  g_free(db_fn_omemo);
  omemo_devicelist_destroy(dl_p);
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
#define NUM_OF_SIGNALS 6

const char * signal_names[NUM_OF_SIGNALS] = {
  "lurch-id-show",
  "lurch-id-list",
  "lurch-id-remove",
  "lurch-enable-im",
  "lurch-disable-im",
  "lurch-fp-get"
};

const void * signal_handlers[NUM_OF_SIGNALS] = {
  lurch_api_id_show_handler,
  lurch_api_id_list_handler,
  lurch_api_id_remove_handler,
  lurch_api_enable_im_handler,
  lurch_api_disable_im_handler,
  lurch_api_fp_get_handler
};

const lurch_api_handler_t signal_handler_types[NUM_OF_SIGNALS] = {
  LURCH_API_HANDLER_ACC_CB_DATA,
  LURCH_API_HANDLER_ACC_CB_DATA,
  LURCH_API_HANDLER_ACC_DID_CB_DATA,
  LURCH_API_HANDLER_ACC_JID_CB_DATA,
  LURCH_API_HANDLER_ACC_JID_CB_DATA,
  LURCH_API_HANDLER_ACC_CB_DATA
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