#include <string.h>
#include <purple.h>

#include "axc.h"

#include "lurch_util.h"

/**
 * Log wrapper for AXC
 *
 * @param level	an AXC_LOG level
 * @param msg 	the log message
 * @param len	the length of the message
 * @param ctx_p	the axc context
 */
void lurch_util_axc_log_func(int level, const char * msg, size_t len, void * user_data) {
  (void) len;
  axc_context * ctx_p = (axc_context *) user_data;
  int log_level = axc_context_get_log_level(ctx_p);

  switch(level) {
    case AXC_LOG_ERROR:
      if (log_level >= AXC_LOG_ERROR) {
        purple_debug_error("lurch", "[AXC ERROR] %s\n", msg);
      }
      break;
    case AXC_LOG_WARNING:
      if (log_level >= AXC_LOG_WARNING) {
        purple_debug_warning("lurch", "[AXC WARNING] %s\n", msg);
      }
      break;
    case AXC_LOG_NOTICE:
      if (log_level >= AXC_LOG_NOTICE) {
        purple_debug_info("lurch", "[AXC NOTICE] %s\n", msg);
      }
      break;
    case AXC_LOG_INFO:
      if (log_level >= AXC_LOG_INFO) {
        purple_debug_info("lurch", "[AXC INFO] %s\n", msg);
      }
      break;
    case AXC_LOG_DEBUG:
      if (log_level >= AXC_LOG_DEBUG) {
        purple_debug_misc("lurch", "[AXC DEBUG] %s\n", msg);
      }
      break;
    default:
      purple_debug_misc("lurch", "[AXC %d] %s\n", level, msg);
      break;
  }
}

/**
 * Creates and initializes the axc context.
 *
 * @param uname The username.
 * @param ctx_pp Will point to an initialized axc context on success.
 * @return 0 on success, negative on error.
 */
int lurch_util_axc_get_init_ctx(char * uname, axc_context ** ctx_pp) {
  int ret_val = 0;
  char * err_msg_dbg = (void *) 0;

  axc_context * ctx_p = (void *) 0;
  char * db_fn = (void *) 0;

  ret_val = axc_context_create(&ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to create axc context");
    goto cleanup;
  }

  db_fn = lurch_util_uname_get_db_fn(uname, LURCH_DB_NAME_AXC);
  ret_val = axc_context_set_db_fn(ctx_p, db_fn, strlen(db_fn));
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to set axc db filename");
    goto cleanup;
  }

  if (purple_prefs_get_bool(LURCH_PREF_AXC_LOGGING)) {
      axc_context_set_log_func(ctx_p, lurch_util_axc_log_func);
      axc_context_set_log_level(ctx_p, purple_prefs_get_int(LURCH_PREF_AXC_LOGGING_LEVEL));
  }

  ret_val = axc_init(ctx_p);
  if (ret_val) {
    err_msg_dbg = g_strdup_printf("failed to init axc context");
    goto cleanup;
  }

  if (purple_prefs_get_bool(LURCH_PREF_AXC_LOGGING)) {
    signal_context_set_log_function(axc_context_get_axolotl_ctx(ctx_p), lurch_util_axc_log_func);
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

char * lurch_util_uname_strip(const char * uname) {
  char ** split;
  char * stripped;

  if (!uname || strlen(uname) == 0) {
    return (void *) 0;
  }

  split = g_strsplit(uname, "/", 2);
  stripped = g_strdup(split[0]);

  g_strfreev(split);

  return stripped;
}

char * lurch_util_uname_get_db_fn(const char * uname, const char * which) {
  return g_strconcat(purple_user_dir(), "/", uname, "_", which, LURCH_DB_SUFFIX, NULL);
}

char * lurch_util_fp_get_printable(const char * fp) {
  char ** split = (void *) 0;
  char * temp1 = (void *) 0;
  char * temp2 = (void *) 0;

  if (!fp || strlen(fp) != 95) {
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