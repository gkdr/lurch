#include <inttypes.h>
#include <glib.h>
#include <purple.h>

#include "axc.h"
#include "libomemo.h"
#include "libomemo_storage.h"

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

typedef enum {
  LURCH_API_HANDLER_ACC_CB_DATA = 0,
  LURCH_API_HANDLER_ACC_JID_CB_DATA
} lurch_api_handler_t;

/**
 * When adding a new signal: increase this number and add the name, handler function, and handler function type
 * to the respective array.
 */
#define NUM_OF_SIGNALS 5

const char * signal_names[NUM_OF_SIGNALS] = {
  "lurch-id-show",
  "lurch-id-list",
  "lurch-enable-im",
  "lurch-disable-im",
  "lurch-fp-get"
};

const void * signal_handlers[NUM_OF_SIGNALS] = {
  lurch_api_id_show_handler,
  lurch_api_id_list_handler,
  lurch_api_enable_im_handler,
  lurch_api_disable_im_handler,
  lurch_api_fp_get_handler
};

const lurch_api_handler_t signal_handler_types[NUM_OF_SIGNALS] = {
  LURCH_API_HANDLER_ACC_CB_DATA,
  LURCH_API_HANDLER_ACC_CB_DATA,
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