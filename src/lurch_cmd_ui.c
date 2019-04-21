#include <inttypes.h>
#include <glib.h>
#include <purple.h>

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
    // add "status"
    " - '/lurch help': Displays this message.\n" // X
    " - '/lurch uninstall': Uninstalls this device from OMEMO by removing its device ID from the devicelist.";

    lurch_cmd_print(conv_p, help_message);
}

void lurch_id_show_print(int32_t err, uint32_t id, void * user_data_p) {
  PurpleConversation * conv_p = (PurpleConversation *) user_data_p;

  if (err) {
    lurch_cmd_print(conv_p, "An error occured when trying to retrieve this device's ID. Check the debug log for details.");
  } else {
    lurch_cmd_print(conv_p, g_strdup_printf("id from callback is %i", id));
  }
}

static void lurch_cmd_id(PurpleConversation * conv_p, const char * arg) {
  char * msg = (void *) 0;
  char * err_msg = (void *) 0;

  if (!g_strcmp0(arg, "show")) {
    purple_signal_emit(purple_plugins_get_handle(), "lurch-id-show", purple_conversation_get_account(conv_p), lurch_id_show_print, conv_p);
  } else {
    msg = g_strdup("Valid argument for 'id' is 'show'.");
  }

  if (err_msg) {
    lurch_cmd_print_err(conv_p, err_msg);
  } else if (msg) {
    lurch_cmd_print(conv_p, msg);
  }

  free(msg);
  free(err_msg);
}

typedef void (*LurchIdShowCallback)(uint32_t id, void * data_p);

PurpleCmdRet lurch_cmd_func_v2(PurpleConversation * conv_p,
                                   const gchar * cmd,
                                   gchar ** args,
                                   gchar ** error,
                                   void * data_p) {
  const char * command = args[0];

  if (!g_strcmp0(command, "help")) {
    lurch_cmd_help(conv_p);
  } else if (!g_strcmp0(command, "id")) {
    lurch_cmd_id(conv_p, args[1]);
  } else {
    lurch_cmd_print(conv_p, "No such command. Type '/lurch help' for a list of available commands.");
  }

  return PURPLE_CMD_RET_OK;
}