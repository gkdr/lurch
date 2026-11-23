#include <string.h>
#include <purple.h>

#include "iq.h"
#include "jabber.h"

#include "axc.h"

#include "lurch_util.h"

#define PUBSUB_XMLNS        "http://jabber.org/protocol/pubsub"
#define PUBSUB_OWNER_XMLNS  PUBSUB_XMLNS "#owner"
#define PUBSUB_ERRORS_XMLNS PUBSUB_XMLNS "#errors"
#define STANZA_ERRORS_XMLNS "urn:ietf:params:xml:ns:xmpp-stanzas"
#define FORM_TYPE_PUBLISH   PUBSUB_XMLNS "#publish-options"
#define FORM_TYPE_NODE_CONF PUBSUB_XMLNS "#node_config"

typedef enum {
  LURCH_PEP_PUBLISH_FIRST_TRY,   // with options, node might be configured differently
  LURCH_PEP_PUBLISH_RECONFIGURED,// with options, after an attempt to reconfigure the node
  LURCH_PEP_PUBLISH_NO_OPTIONS   // last resort
} lurch_pep_publish_stage;

typedef struct {
  xmlnode * publish_node_p;
  lurch_pep_publish_stage stage;
  gboolean multiple_items;
} lurch_pep_publish_state;

static void lurch_pep_publish_send(JabberStream * js_p, lurch_pep_publish_state * state_p);

static void lurch_pep_publish_state_destroy(lurch_pep_publish_state * state_p) {
  xmlnode_free(state_p->publish_node_p);
  g_free(state_p);
}

/**
 * Creates a filled out data form requesting the 'open' access model, and optionally to keep as many items as possible.
 */
static xmlnode * lurch_pep_open_access_form_create(const char * form_type, gboolean multiple_items) {
  xmlnode * form_p = xmlnode_new("x");
  xmlnode_set_namespace(form_p, "jabber:x:data");
  xmlnode_set_attrib(form_p, "type", "submit");

  xmlnode * field_p = xmlnode_new_child(form_p, "field");
  xmlnode_set_attrib(field_p, "var", "FORM_TYPE");
  xmlnode_set_attrib(field_p, "type", "hidden");
  xmlnode_insert_data(xmlnode_new_child(field_p, "value"), form_type, -1);

  field_p = xmlnode_new_child(form_p, "field");
  xmlnode_set_attrib(field_p, "var", "pubsub#access_model");
  xmlnode_insert_data(xmlnode_new_child(field_p, "value"), "open", -1);

  if (multiple_items) {
    field_p = xmlnode_new_child(form_p, "field");
    xmlnode_set_attrib(field_p, "var", "pubsub#max_items");
    xmlnode_insert_data(xmlnode_new_child(field_p, "value"), "max", -1);
  }

  return form_p;
}

/**
 * Failing to reconfigure is not final as the publish might work anyway, so just go on with the next attempt.
 */
static void lurch_pep_reconfigure_cb(JabberStream * js_p, const char * from, JabberIqType type, const char * id, xmlnode * packet_p, gpointer data_p) {
  lurch_pep_publish_state * state_p = data_p;
  (void) from;
  (void) id;
  (void) packet_p;

  if (type != JABBER_IQ_RESULT) {
    purple_debug_warning("lurch", "%s: failed to reconfigure node %s\n", __func__, xmlnode_get_attrib(state_p->publish_node_p, "node"));
  }

  state_p->stage = LURCH_PEP_PUBLISH_RECONFIGURED;
  lurch_pep_publish_send(js_p, state_p);
}

static void lurch_pep_reconfigure_send(JabberStream * js_p, lurch_pep_publish_state * state_p) {
  JabberIq * jiq_p = jabber_iq_new(js_p, JABBER_IQ_SET);

  xmlnode * pubsub_node_p = xmlnode_new_child(jiq_p->node, "pubsub");
  xmlnode_set_namespace(pubsub_node_p, PUBSUB_OWNER_XMLNS);

  xmlnode * configure_node_p = xmlnode_new_child(pubsub_node_p, "configure");
  xmlnode_set_attrib(configure_node_p, "node", xmlnode_get_attrib(state_p->publish_node_p, "node"));
  xmlnode_insert_child(configure_node_p, lurch_pep_open_access_form_create(FORM_TYPE_NODE_CONF, state_p->multiple_items));

  jabber_iq_set_callback(jiq_p, lurch_pep_reconfigure_cb, state_p);
  jabber_iq_send(jiq_p);
}

static void lurch_pep_publish_cb(JabberStream * js_p, const char * from, JabberIqType type, const char * id, xmlnode * packet_p, gpointer data_p) {
  lurch_pep_publish_state * state_p = data_p;
  const char * node_name = xmlnode_get_attrib(state_p->publish_node_p, "node");
  (void) from;
  (void) id;

  if (type == JABBER_IQ_RESULT) {
    purple_debug_info("lurch", "%s: published to node %s\n", __func__, node_name);
    lurch_pep_publish_state_destroy(state_p);
    return;
  }

  xmlnode * error_node_p = xmlnode_get_child(packet_p, "error");
  gboolean precondition_not_met = error_node_p
                                  && xmlnode_get_child_with_namespace(error_node_p, "precondition-not-met", PUBSUB_ERRORS_XMLNS);

  if (state_p->stage == LURCH_PEP_PUBLISH_FIRST_TRY && precondition_not_met) {
    purple_debug_info("lurch", "%s: node %s is configured differently, reconfiguring it\n", __func__, node_name);
    lurch_pep_reconfigure_send(js_p, state_p);
    return;
  }

  if (state_p->stage != LURCH_PEP_PUBLISH_NO_OPTIONS) {
    purple_debug_warning("lurch", "%s: publishing to node %s with the open access model failed, contacts might not be able to access it\n", __func__, node_name);
    state_p->stage = LURCH_PEP_PUBLISH_NO_OPTIONS;
    lurch_pep_publish_send(js_p, state_p);
    return;
  }

  purple_debug_error("lurch", "%s: failed to publish to node %s\n", __func__, node_name);
  lurch_pep_publish_state_destroy(state_p);
}

static void lurch_pep_publish_send(JabberStream * js_p, lurch_pep_publish_state * state_p) {
  JabberIq * jiq_p = jabber_iq_new(js_p, JABBER_IQ_SET);

  xmlnode * pubsub_node_p = xmlnode_new_child(jiq_p->node, "pubsub");
  xmlnode_set_namespace(pubsub_node_p, PUBSUB_XMLNS);

  xmlnode_insert_child(pubsub_node_p, xmlnode_copy(state_p->publish_node_p));

  if (state_p->stage != LURCH_PEP_PUBLISH_NO_OPTIONS) {
    xmlnode * options_node_p = xmlnode_new_child(pubsub_node_p, "publish-options");
    xmlnode_insert_child(options_node_p, lurch_pep_open_access_form_create(FORM_TYPE_PUBLISH, state_p->multiple_items));
  }

  jabber_iq_set_callback(jiq_p, lurch_pep_publish_cb, state_p);
  jabber_iq_send(jiq_p);
}

static void lurch_pep_publish_start(JabberStream * js_p, xmlnode * publish_node_p, gboolean multiple_items) {
  lurch_pep_publish_state * state_p = g_new0(lurch_pep_publish_state, 1);
  state_p->publish_node_p = publish_node_p;
  state_p->stage = LURCH_PEP_PUBLISH_FIRST_TRY;
  state_p->multiple_items = multiple_items;

  lurch_pep_publish_send(js_p, state_p);
}

void lurch_util_pep_publish(JabberStream * js_p, xmlnode * publish_node_p) {
  xmlnode * item_node_p = xmlnode_get_child(publish_node_p, "item");
  if (item_node_p) {
    xmlnode_set_attrib(item_node_p, "id", "current");
  }

  lurch_pep_publish_start(js_p, publish_node_p, FALSE);
}

void lurch_util_pep_publish_multi(JabberStream * js_p, xmlnode * publish_node_p) {
  lurch_pep_publish_start(js_p, publish_node_p, TRUE);
}

typedef struct {
  JabberPEPHandler * cb;
} lurch_pep_request_state;

static void lurch_pep_request_all_items_cb(JabberStream * js_p, const char * from, JabberIqType type, const char * id, xmlnode * packet_p, gpointer data_p) {
  lurch_pep_request_state * state_p = data_p;
  xmlnode * pubsub_p = xmlnode_get_child_with_namespace(packet_p, "pubsub", PUBSUB_XMLNS);
  xmlnode * error_p = xmlnode_get_child(packet_p, "error");
  (void) id;

  if (type == JABBER_IQ_RESULT && pubsub_p) {
    state_p->cb(js_p, from, xmlnode_get_child(pubsub_p, "items"));
  } else if (error_p && xmlnode_get_child_with_namespace(error_p, "item-not-found", STANZA_ERRORS_XMLNS)) {
    state_p->cb(js_p, from, (void *) 0);
  } else {
    // e.g. a timeout, or a node that is not accessible, which says nothing about whether it exists
    purple_debug_info("lurch", "%s: could not get a node from %s\n", __func__, from ? from : "the own account");
  }

  g_free(state_p);
}

void lurch_util_pep_request_all_items(JabberStream * js_p, const char * to, const char * node, JabberPEPHandler * cb) {
  lurch_pep_request_state * state_p = g_new0(lurch_pep_request_state, 1);
  state_p->cb = cb;

  JabberIq * jiq_p = jabber_iq_new(js_p, JABBER_IQ_GET);
  xmlnode_set_attrib(jiq_p->node, "to", to);
  xmlnode * pubsub_p = xmlnode_new_child(jiq_p->node, "pubsub");
  xmlnode_set_namespace(pubsub_p, PUBSUB_XMLNS);
  xmlnode_set_attrib(xmlnode_new_child(pubsub_p, "items"), "node", node);

  jabber_iq_set_callback(jiq_p, lurch_pep_request_all_items_cb, state_p);
  jabber_iq_send(jiq_p);
}

xmlnode * lurch_util_pep_item_current(xmlnode * items_p) {
  xmlnode * last_p = (void *) 0;

  for (xmlnode * item_p = xmlnode_get_child(items_p, "item"); item_p; item_p = xmlnode_get_next_twin(item_p)) {
    if (!g_strcmp0(xmlnode_get_attrib(item_p, "id"), "current")) {
      return item_p;
    }
    last_p = item_p;
  }

  return last_p;
}

void lurch_util_pep_retract(JabberStream * js_p, const char * node, const char * item_id) {
  JabberIq * jiq_p = jabber_iq_new(js_p, JABBER_IQ_SET);
  xmlnode * pubsub_p = xmlnode_new_child(jiq_p->node, "pubsub");
  xmlnode_set_namespace(pubsub_p, PUBSUB_XMLNS);
  xmlnode * retract_p = xmlnode_new_child(pubsub_p, "retract");
  xmlnode_set_attrib(retract_p, "node", node);
  xmlnode_set_attrib(xmlnode_new_child(retract_p, "item"), "id", item_id);

  jabber_iq_send(jiq_p);
}

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
    err_msg_dbg = g_strdup_printf("failed to set axc db filename to %s", db_fn);
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
    g_free(err_msg_dbg);
  }

  g_free (db_fn);
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

char * lurch_util_fp_get_printable(axc_buf * key_buf_p) {
  gchar * fp = (void *) 0;
  char ** split = (void *) 0;
  const size_t fp_parts_len = 32;
  char * printable = (void *) 0;
  const size_t printable_len = 72;

  if (!key_buf_p) {
    purple_debug_warning("lurch", "%s: Key buffer is null, aborting\n", __func__);
    goto cleanup;
  }

  fp = purple_base16_encode_chunked(axc_buf_get_data(key_buf_p), axc_buf_get_len(key_buf_p));
  if (!fp || strlen(fp) != 98) {
    purple_debug_warning("lurch", "%s: Unexpected fingerprint length, aborting\n", __func__);
    goto cleanup;
  }

  // first part is dismissed for display
  split = g_strsplit(fp, ":", fp_parts_len + 1);
  printable = g_malloc0(printable_len);

  for (int i = 1; i <= fp_parts_len; i++) {
    g_strlcat(printable, split[i], printable_len);

    if (i % 4 == 0 && i != fp_parts_len) {
      g_strlcat(printable, " ", printable_len);
    }
  }

cleanup:
  g_free(fp);
  g_strfreev(split);

  return printable;
}

