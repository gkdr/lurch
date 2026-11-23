#pragma once

#include <purple.h>

#include "jabber.h"

/**
 * OMEMO 2 (urn:xmpp:omemo:2) for one-on-one conversations, next to the version in the eu.siacs.conversations.axolotl
 * namespace that is implemented by libomemo and axc.
 *
 * Both share the device ID and the identity key, so that this device is one device for clients which implement both.
 * Everything else is kept separately, in LURCH_DB_NAME_OM2.
 *
 * Devices which are on the devicelists of both versions keep getting the old version, as that is what has been tested
 * the most. Only devices that exclusively use OMEMO 2 get it.
 */

#define LURCH_DB_NAME_OM2 "omemo2"
#define LURCH_NS_OM2      "urn:xmpp:omemo:2"

/** Has to be called when the plugin is loaded. */
void lurch_om2_init(void);

/** Has to be called after signing on, when the identity key exists. Prepares the keys and announces this device. */
void lurch_om2_account_connected(JabberStream * js_p);

/** Fetches the devicelist of a contact. */
void lurch_om2_devicelist_request(JabberStream * js_p, const char * bare_jid);

/** @return 1 if the contact is known to use OMEMO 2 on any device, and 0 if not. */
int lurch_om2_contact_available(const char * uname, const char * bare_jid);

/** @return 1 if there is a session with any device of the contact, and 0 if not. */
int lurch_om2_contact_has_session(const char * uname, const char * bare_jid);

/**
 * Handles an outgoing one-on-one message.
 *
 * Devices using just OMEMO 2 get their own stanza, independently of what happens to the original.
 * The original still has to be handled by the caller, unless the contact only has such devices. In that case it is
 * consumed: the pointer is set to NULL, and the message is sent as soon as the bundles were fetched.
 *
 * @param js_p The stream.
 * @param recipient The bare JID of the recipient.
 * @param legacy_ids_p The IDs on the recipient's old devicelist, as uint32_t *.
 * @param own_legacy_ids_p The IDs on the own old devicelist, as uint32_t *.
 * @param stanza_pp The stanza.
 */
void lurch_om2_message_send(JabberStream * js_p, const char * recipient, GList * legacy_ids_p, GList * own_legacy_ids_p, xmlnode ** stanza_pp);

/**
 * Handles an incoming message containing an <encrypted> element of this version.
 *
 * @param js_p The stream.
 * @param stanza_pp The stanza. Will contain the plaintext if there is one, or NULL if it is not to be processed further.
 * @return 1 if the message was handled. 0 if it does not contain a key for this device, so that it is up to the caller.
 */
int lurch_om2_message_receive(JabberStream * js_p, xmlnode ** stanza_pp);

/**
 * Handles the '/lurch omemo2' command.
 *
 * @param conv_p The conversation it was used in.
 * @param arg The argument, can be NULL.
 */
void lurch_om2_cmd(PurpleConversation * conv_p, const char * arg);
