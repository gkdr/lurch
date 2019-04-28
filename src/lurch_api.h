#pragma once

/**
 * Initializes the API by registering the signals and signal handlers.
 */
void lurch_api_init();

/**
* Unregisters the signals and disconnects the signal handlers.
*/
void lurch_api_unload();