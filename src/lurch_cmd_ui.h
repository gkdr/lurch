#pragma once

#include <glib.h>
#include <purple.h>

PurpleCmdRet lurch_cmd_func_v2(PurpleConversation * conv_p,
                                   const gchar * cmd,
                                   gchar ** args,
                                   gchar ** error,
                                   void * data_p);