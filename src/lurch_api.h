#pragma once

#define LURCH_ERR                    -1000000
#define LURCH_ERR_NOMEM              -1000001
#define LURCH_ERR_NO_BUNDLE          -1000010
#define LURCH_ERR_DEVICE_NOT_IN_LIST -1000100

/**
 * Initializes the API by registering the signals and signal handlers.
 */
void lurch_api_init();

/**
* Unregisters the signals and disconnects the signal handlers.
*/
void lurch_api_unload();

typedef enum {
    LURCH_STATUS_DISABLED = 0,  // manually disabled
    LURCH_STATUS_NOT_SUPPORTED, // no OMEMO support, i.e. there is no devicelist node
    LURCH_STATUS_NO_SESSION,    // OMEMO is supported, but there is no libsignal session yet
    LURCH_STATUS_OK             // OMEMO is supported and session exists
} lurch_status_t;


/**
 * USAGE
 * 
 * Some functions users might be interested in can be called via libpurple signals.
 * Thus, the libpurple commands interface uses these as well and lurch_cmd_ui.c is therefore full of examples.
 * Generally, the workflow is as follows:
 *
 * - Find the signal you need and check the handler function's parameters.
 *   Generally, you will need to pass the user's PurpleAccount, a callback, and the data to be passed to the callback.
 *   For some functions, the conversation partner's or chat's JID is also required.
 * 
 * - Write the callback function needed by the handler.
 *   The first parameter is an error value. It is generally the return value from the called functions.
 *   If it is non-zero, an error occured somewhere and there should be more information in the debug log.
 *   Otherwise, the call succeeded and the following parameters will be set.
 *   The last parameter is the data given when emitting the signal.
 * 
 * - Emit the signal using the plugin system handle as the instance and pass the necessary data.
 *   If you do it wrong, there will be no compiler errors and the pointers are gibberish, so take care.
 *   You can easily get the plugin system handle anywhere by calling purple_plugins_get_handle().
 */