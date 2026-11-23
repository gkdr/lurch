#pragma once

#include <stddef.h>
#include <stdint.h>

#include "lurch_om2_crypto.h"

/**
 * The cryptographic protocol of OMEMO 2 (urn:xmpp:omemo:2), see XEP-0384: X3DH, the Double Ratchet, the protobuf
 * structures and the payload encryption. Does not know about XMPP or any storage.
 *
 * All functions return 0 on success and a negative value on error.
 * All buffers returned using double pointers are allocated with g_malloc(), g_free() them when done.
 *
 * The state must only be persisted after a successful call. A failed decryption can leave it changed, which is on
 * purpose: the input is not authenticated at that point and must not have any effect. Load it again instead.
 */

#define LURCH_OM2_ERR               -1
#define LURCH_OM2_ERR_DUPLICATE     -2 // the message was already received, this must not be reported to the user
#define LURCH_OM2_ERR_AUTH          -3 // the message is not authentic
#define LURCH_OM2_ERR_TOO_MANY_SKIP -4 // too many messages would have to be skipped

#define LURCH_OM2_MAX_SKIP          1000 // recommended by the XEP, both per session and per message
#define LURCH_OM2_HEARTBEAT_COUNTER 53
#define LURCH_OM2_KEY_AND_TAG_LEN   (LURCH_OM2_KEY_LEN + LURCH_OM2_TAG_LEN)
#define LURCH_OM2_EMPTY_LEN         LURCH_OM2_KEY_LEN

typedef struct lurch_om2_session lurch_om2_session;

/** The other side's public keys needed for starting a session, as published in their bundle. */
typedef struct {
  uint8_t ik_ed[LURCH_OM2_KEY_LEN];
  uint32_t spk_id;
  uint8_t spk[LURCH_OM2_KEY_LEN];
  uint8_t spk_sig[LURCH_OM2_SIG_LEN];
  uint32_t pk_id;
  uint8_t pk[LURCH_OM2_KEY_LEN];
} lurch_om2_bundle;

/** The parsed form of an OMEMOKeyExchange. The message is a pointer into the parsed buffer. */
typedef struct {
  uint32_t pk_id;
  uint32_t spk_id;
  uint8_t ik_ed[LURCH_OM2_KEY_LEN];
  uint8_t ek[LURCH_OM2_KEY_LEN];
  const uint8_t * msg_p;
  size_t msg_len;
} lurch_om2_key_exchange;

/**
 * Starts a session actively, after verifying the signature of the signed PreKey.
 *
 * @param own_ik_p The own identity key pair, in its Curve25519 form.
 */
int lurch_om2_session_create_active(const lurch_om2_keypair * own_ik_p, const lurch_om2_bundle * bundle_p, lurch_om2_session ** session_pp);

/**
 * Starts a session passively, after receiving an OMEMOKeyExchange.
 * The first message still has to be decrypted to know whether it is authentic.
 *
 * @param own_ik_p  The own identity key pair, in its Curve25519 form.
 * @param own_spk_p The own signed PreKey with the ID of the key exchange.
 * @param own_pk_p  The own PreKey with the ID of the key exchange.
 */
int lurch_om2_session_create_passive(const lurch_om2_keypair * own_ik_p,
                                     const lurch_om2_keypair * own_spk_p,
                                     const lurch_om2_keypair * own_pk_p,
                                     const lurch_om2_key_exchange * kex_p,
                                     lurch_om2_session ** session_pp);

void lurch_om2_session_destroy(lurch_om2_session * session_p);

int lurch_om2_session_serialize(const lurch_om2_session * session_p, uint8_t ** out_pp, size_t * out_len_p);
int lurch_om2_session_deserialize(const uint8_t * in_p, size_t in_len, lurch_om2_session ** session_pp);

/**
 * Encrypts a key for this session's device, or the zeros of an empty message.
 *
 * @param out_pp Will contain the content of the <key> element.
 * @param is_kex_p Will be set to 1 if it is an OMEMOKeyExchange, which will be the case until something was received.
 */
int lurch_om2_session_encrypt(lurch_om2_session * session_p, const uint8_t * plain_p, size_t plain_len, uint8_t ** out_pp, size_t * out_len_p, int * is_kex_p);

/**
 * Decrypts an OMEMOAuthenticatedMessage.
 *
 * @param needs_heartbeat_p Will be set to 1 if an empty message should be sent in response.
 */
int lurch_om2_session_decrypt(lurch_om2_session * session_p, const uint8_t * msg_p, size_t msg_len, uint8_t ** out_pp, size_t * out_len_p, int * needs_heartbeat_p);

/** @return 1 if this session was started with this ephemeral key from the other side, so that it is not a new one. */
int lurch_om2_session_has_remote_ek(const lurch_om2_session * session_p, const uint8_t * ek_p);

/** @return The other side's identity key. */
const uint8_t * lurch_om2_session_get_remote_ik(const lurch_om2_session * session_p);

/** Parses an OMEMOKeyExchange. The result points into the input, so it has to stay around. */
int lurch_om2_key_exchange_parse(const uint8_t * in_p, size_t in_len, lurch_om2_key_exchange * kex_p);

/**
 * Encrypts the payload.
 *
 * @param key_and_tag_p Will contain what has to be encrypted for each device, must have space for LURCH_OM2_KEY_AND_TAG_LEN bytes.
 */
int lurch_om2_payload_encrypt(const uint8_t * plain_p, size_t plain_len, uint8_t * key_and_tag_p, uint8_t ** out_pp, size_t * out_len_p);

/** Decrypts the payload, after verifying it. */
int lurch_om2_payload_decrypt(const uint8_t * key_and_tag_p, const uint8_t * in_p, size_t in_len, uint8_t ** out_pp, size_t * out_len_p);
