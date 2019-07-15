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

/**
 * SIGNAL: lurch-id-list
 *
 * Gets the specified account's OMEMO devicelist and passes it to the callback as a GList containing uint32_t *.
 * To access the actual ID, cast the data member to a uint32_t * and dereference it.
 * This device's ID will be the first item in the list.
 */
void lurch_api_id_list_handler(PurpleAccount * acc_p, void (*cb)(int32_t err, GList * id_list, void * user_data_p), void * user_data_p);

/**
 * SIGNAL: lurch-id-remove
 *
 * Removes the specified OMEMO device ID from the specified account's devicelist.
 */
void lurch_api_id_remove_handler(PurpleAccount * acc_p, uint32_t device_id, void (*cb)(int32_t err, void * user_data_p), void * user_data_p);