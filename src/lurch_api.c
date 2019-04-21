#include <inttypes.h>
#include <purple.h>

#include "jabber.h"
#include "axc.h"

#include "lurch_util.h"

void lurch_api_id_show_handler(PurpleAccount * acc_p, void (*cb)(int32_t err, uint32_t id, void * user_data_p), void * user_data_p) {
  int ret_val = 0;
  int32_t err = 0;
  char * uname = (void *) 0;
  axc_context * axc_ctx_p = (void *) 0;
  uint32_t id = 0;

  uname = lurch_util_uname_strip(purple_account_get_username(acc_p));
  
  ret_val = lurch_util_axc_get_init_ctx(uname, &axc_ctx_p);
  if (ret_val) {
    purple_debug_error("lurch-api", "Failed to create axc ctx.\n");
    err = ret_val;
    goto cleanup;
  }

  ret_val = axc_get_device_id(axc_ctx_p, &id);
  if (ret_val) {
    purple_debug_error("lurch-api", "Failed to access axc db %s. Does the path seem correct?", axc_context_get_db_fn(axc_ctx_p));
    err = ret_val;
    goto cleanup;
  }

cleanup:
  cb(err, id, user_data_p);

  axc_context_destroy_all(axc_ctx_p);
  g_free(uname);
}

void lurch_api_init() {
    purple_signal_register(
        purple_plugins_get_handle(),
        "lurch-id-show",
        purple_marshal_VOID__POINTER_POINTER_POINTER,
        NULL,
        3,
        purple_value_new(PURPLE_TYPE_SUBTYPE, PURPLE_SUBTYPE_ACCOUNT),
        purple_value_new(PURPLE_TYPE_POINTER),
        purple_value_new(PURPLE_TYPE_POINTER)
    );

    purple_signal_connect(
        purple_plugins_get_handle(),
        "lurch-id-show",
        "lurch-api",
        PURPLE_CALLBACK(lurch_api_id_show_handler),
        NULL
    );
}