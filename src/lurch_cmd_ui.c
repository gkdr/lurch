#include <inttypes.h>
#include <glib.h>
#include <purple.h>

#include "jutil.h"

#include "libomemo.h"

static void lurch_cmd_print(PurpleConversation * conv_p, const char * msg) {
  purple_conversation_write(conv_p, "lurch", msg, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG, time((void *) 0));  
}

static void lurch_cmd_print_err(PurpleConversation * conv_p, const char * msg) {
  purple_conversation_write(conv_p, "lurch", msg, PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_ERROR, time((void *) 0));  
}

static void lurch_cmd_help(PurpleConversation * conv_p) {
  const char * help_message = 
    "The following commands exist to interact with the lurch plugin:\n\n"
    " - '/lurch enable': Enables OMEMO encryption for this conversation. On by default for regular conversations, off for group chats.\n"
    " - '/lurch disable': Disables OMEMO encryption for this conversation.\n"
    " - '/lurch id show': Displays this device's ID.\n"
    " - '/lurch id list': Displays this account's device list.\n"
    " - '/lurch id remove <id>': Removes the device ID <id> from this account's device list.\n"
    " - '/lurch fp show': Displays this device's key fingerprint.\n"
    " - '/lurch fp conv': Displays the fingerprints of all devices participating in this conversation.\n"
    //TODO: add "status"
    " - '/lurch help': Displays this message.\n"
    " - '/lurch uninstall': Uninstalls this device from OMEMO by removing its device ID from the devicelist.";

    lurch_cmd_print(conv_p, help_message);
}

void lurch_id_show_print(int32_t err, uint32_t id, void * user_data_p) {
  PurpleConversation * conv_p = (PurpleConversation *) user_data_p;

  char * msg = (void *) 0;

  if (err) {
    lurch_cmd_print_err(conv_p, "An error occured when trying to retrieve this device's ID. Check the debug log for details.");
    return;
  }

  msg = g_strdup_printf("This device's ID is %i", id); 
  lurch_cmd_print(conv_p, msg);

  g_free(msg);
}

void lurch_id_list_print(int32_t err, GList * id_list, void * user_data_p) {
  PurpleConversation * conv_p = (PurpleConversation *) user_data_p;

  char * temp_msg_1 = g_strdup("Your devicelist is:\n");
  char * temp_msg_2 = (void *) 0;
  char * temp_msg_3 = (void *) 0;

  GList * curr_p = (void *) 0;

  if (err) {
    lurch_cmd_print_err(conv_p, "An error occured when trying to retrieve your ID list. Check the debug log for details.");
    return;
  }

  for (curr_p = id_list; curr_p; curr_p = curr_p->next) {
    temp_msg_2 = g_strdup_printf("%i\n", omemo_devicelist_list_data(curr_p));
    temp_msg_3 = g_strconcat(temp_msg_1, temp_msg_2, NULL);

    g_free(temp_msg_1);
    temp_msg_1 = temp_msg_3;
    g_free(temp_msg_2);

    temp_msg_2 = (void *) 0;
    temp_msg_3 = (void *) 0;
  }

  lurch_cmd_print(conv_p, temp_msg_1);

  g_free(temp_msg_1);
}

void lurch_enable_print(int32_t err, void * user_data_p) {
  PurpleConversation * conv_p = (PurpleConversation *) user_data_p;

  if (err) {
    lurch_cmd_print_err(conv_p, "Failed to enable OMEMO for this conversation.");
    return;
  }
  
  purple_conversation_autoset_title(conv_p);
  lurch_cmd_print(conv_p, "Successfully enabled OMEMO.");
}

void lurch_disable_print(int32_t err, void * user_data_p) {
  PurpleConversation * conv_p = (PurpleConversation *) user_data_p;

  if (err) {
    lurch_cmd_print_err(conv_p, "Failed to disable OMEMO for this conversation.");
    return;
  }
  
  purple_conversation_autoset_title(conv_p);
  lurch_cmd_print(conv_p, "Successfully disabled OMEMO.");
}

void lurch_fp_show_print(int32_t err, const char * fp_printable, void * user_data_p) {
  PurpleConversation * conv_p = (PurpleConversation *) user_data_p;
  char * msg = (void *) 0;

  if (err) {
    lurch_cmd_print_err(conv_p, "Failed to get this device's fingerprint. Check the debug log for details.");
    return;
  }

  msg = g_strdup_printf("This device's fingerprint is %s.", fp_printable);
  lurch_cmd_print(conv_p, msg);

  g_free(msg);
}

static void lurch_cmd_id(PurpleConversation * conv_p, const char * arg) {
  PurpleAccount * acc_p = purple_conversation_get_account(conv_p);

  if (!g_strcmp0(arg, "show")) {
    purple_signal_emit(purple_plugins_get_handle(), "lurch-id-show", acc_p, lurch_id_show_print, conv_p);
  } else if (!g_strcmp0(arg, "list")) {
    purple_signal_emit(purple_plugins_get_handle(), "lurch-id-list", acc_p, lurch_id_list_print, conv_p);
  } else {
    lurch_cmd_print(conv_p, "Valid arguments for 'id' are 'show' or 'list'.");
  }
}

static void lurch_cmd_enable(PurpleConversation * conv_p) {
  PurpleConversationType conv_type = purple_conversation_get_type(conv_p);
  char * conv_bare_jid = jabber_get_bare_jid(purple_conversation_get_name(conv_p));

  if (conv_type == PURPLE_CONV_TYPE_IM) {
    purple_signal_emit(purple_plugins_get_handle(), "lurch-enable-im", purple_conversation_get_account(conv_p), conv_bare_jid, lurch_enable_print, conv_p);
  }

  g_free(conv_bare_jid);
}

static void lurch_cmd_disable(PurpleConversation * conv_p) {
  PurpleConversationType conv_type = purple_conversation_get_type(conv_p);
  char * conv_bare_jid = jabber_get_bare_jid(purple_conversation_get_name(conv_p));

  if (conv_type == PURPLE_CONV_TYPE_IM) {
    purple_signal_emit(purple_plugins_get_handle(), "lurch-disable-im", purple_conversation_get_account(conv_p), conv_bare_jid, lurch_disable_print, conv_p);
  }

  g_free(conv_bare_jid);
}

static void lurch_cmd_fp(PurpleConversation * conv_p, const char * arg) {
  PurpleAccount * acc_p = purple_conversation_get_account(conv_p);

  if (!g_strcmp0(arg, "show")) {
    purple_signal_emit(purple_plugins_get_handle(), "lurch-fp-get", acc_p, lurch_fp_show_print, conv_p);
  } else {
    lurch_cmd_print(conv_p, "Valid arguments for 'fp' are 'show'.");
  }
}

PurpleCmdRet lurch_cmd_func_v2(PurpleConversation * conv_p,
                                   const gchar * cmd,
                                   gchar ** args,
                                   gchar ** error,
                                   void * data_p) {
  const char * command = args[0];

  if (!g_strcmp0(command, "help")) {
    lurch_cmd_help(conv_p);
  } else if (!g_strcmp0(command, "enable")) {
    lurch_cmd_enable(conv_p);
  } else if (!g_strcmp0(command, "disable")) {
    lurch_cmd_disable(conv_p);
  } else if (!g_strcmp0(command, "id")) {
    lurch_cmd_id(conv_p, args[1]);
  } else if (!g_strcmp0(command, "fp")) {
    lurch_cmd_fp(conv_p, args[1]);
  } else {
    lurch_cmd_print(conv_p, "No such command. Type '/lurch help' for a list of available commands.");
  }

  return PURPLE_CMD_RET_OK;
}