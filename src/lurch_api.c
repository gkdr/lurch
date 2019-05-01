#include <inttypes.h>
#include <glib.h>
#include <purple.h>

#include "axc.h"
#include "libomemo.h"
#include "libomemo_storage.h"

#include "lurch_util.h"

#define MODULE_NAME "lurch-api"

void lurch_api_id_show_handler(PurpleAccount * acc_p, void (*cb)(int32_t err, uint32_t id, void * user_data_p), void * user_data_p) {
  int ret_val = 0;
  int32_t err = 0;
  char * uname = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t id = 0;

  uname = lurch_util_uname_strip(purple_account_get_username(acc_p));
  
  ret_val = lurch_util_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to create axc ctx.\n");
    err = ret_val;
    goto cleanup;
  }

  ret_val = axc_get_device_id(axc_ctx_p, &id);
  if (ret_val) {
    purple_debug_error(MODULE_NAME, "Failed to access axc db %s. Does the path seem correct?", axc_context_get_db_fn(axc_ctx_p));
    err = ret_val;
    goto cleanup;
  }

cleanup:
  cb(err, id, user_data_p);

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

// const char * signals[2] = {"lurch-id-show", "lurch-id-list"};
// const void * handlers[2] = {lurch_api_id_show_handler, lurch_api_id_list_handler};

void lurch_api_init() {
  void * plugins_handle_p = purple_plugins_get_handle();
    
  purple_signal_register(
    plugins_handle_p,
    "lurch-id-show",
    purple_marshal_VOID__POINTER_POINTER_POINTER,
    NULL,
    3,
    purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_ACCOUNT),
    purple_value_new(PURPLE_TYPE_POINTER),
    purple_value_new(PURPLE_TYPE_POINTER)
  );

  purple_signal_register(
    plugins_handle_p,
    "lurch-id-list",
    purple_marshal_VOID__POINTER_POINTER_POINTER,
    NULL,
    3,
    purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_ACCOUNT),
    purple_value_new(PURPLE_TYPE_POINTER),
    purple_value_new(PURPLE_TYPE_POINTER)
  );

  purple_signal_register(
    plugins_handle_p,
    "lurch-enable-im",
    purple_marshal_VOID__POINTER_POINTER_POINTER_POINTER,
    NULL,
    4,
    purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_ACCOUNT),
    purple_value_new(PURPLE_TYPE_STRING),
    purple_value_new(PURPLE_TYPE_POINTER),
    purple_value_new(PURPLE_TYPE_POINTER)
  );

  purple_signal_connect(
    plugins_handle_p,
    "lurch-id-show",
    MODULE_NAME,
    PURPLE_CALLBACK(lurch_api_id_show_handler),
    NULL
  );

  purple_signal_connect(
    plugins_handle_p,
    "lurch-id-list",
    MODULE_NAME,
    PURPLE_CALLBACK(lurch_api_id_list_handler),
    NULL
  );

  purple_signal_connect(
    plugins_handle_p,
    "lurch-enable-im",
    MODULE_NAME,
    PURPLE_CALLBACK(lurch_api_enable_im_handler),
    NULL
  );
}

void lurch_api_unload() {
  void * plugins_handle_p = purple_plugins_get_handle();

  purple_signal_disconnect(
    plugins_handle_p,
    "lurch-id-show",
    MODULE_NAME,
    PURPLE_CALLBACK(lurch_api_id_show_handler)
  );

  purple_signal_disconnect(
    plugins_handle_p,
    "lurch-id-list",
    MODULE_NAME,
    PURPLE_CALLBACK(lurch_api_id_list_handler)
  );

  purple_signal_disconnect(
    plugins_handle_p,
    "lurch-enable-im",
    MODULE_NAME,
    PURPLE_CALLBACK(lurch_api_enable_im_handler)
  );

  purple_signal_unregister(purple_plugins_get_handle(), "lurch-id-show");
  purple_signal_unregister(purple_plugins_get_handle(), "lurch-id-list");
  purple_signal_unregister(purple_plugins_get_handle(), "lurch-enable-im");
}