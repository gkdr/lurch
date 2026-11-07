#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * Cryptographic primitives for OMEMO 2 (urn:xmpp:omemo:2), see XEP-0384.
 * Unlike libsignal, which is limited to the eu.siacs.conversations.axolotl version of the protocol.
 *
 * All functions return 0 on success and a negative value on error.
 * Key lengths are fixed: public and private keys, hashes and message keys are all LURCH_OM2_KEY_LEN bytes.
 */

#define LURCH_OM2_KEY_LEN 32
#define LURCH_OM2_SIG_LEN 64
#define LURCH_OM2_TAG_LEN 16
#define LURCH_OM2_IV_LEN  16

#define LURCH_OM2_INFO_X3DH    "OMEMO X3DH"
#define LURCH_OM2_INFO_ROOT    "OMEMO Root Chain"
#define LURCH_OM2_INFO_MESSAGE "OMEMO Message Key Material"
#define LURCH_OM2_INFO_PAYLOAD "OMEMO Payload"

typedef struct {
  uint8_t priv[LURCH_OM2_KEY_LEN];
  uint8_t pub[LURCH_OM2_KEY_LEN];
} lurch_om2_keypair;

/** Output is 32 bytes. */
int lurch_om2_hmac(const uint8_t * key_p, size_t key_len, const uint8_t * data_p, size_t data_len, uint8_t * out_p);

/** HKDF-SHA-256 as in RFC 5869, with at most 255 * 32 bytes of output. */
int lurch_om2_hkdf(const uint8_t * salt_p, size_t salt_len,
                   const uint8_t * ikm_p, size_t ikm_len,
                   const char * info,
                   uint8_t * out_p, size_t out_len);

/** Fills the buffer with strong random bytes. */
void lurch_om2_random(uint8_t * out_p, size_t len);

/** Compares in constant time. @return 1 if equal, 0 if not. */
int lurch_om2_equal(const uint8_t * a_p, const uint8_t * b_p, size_t len);

/** Overwrites secrets. */
void lurch_om2_wipe(void * p, size_t len);

/**
 * AES-256-CBC with PKCS#7 padding.
 * The output is allocated using g_malloc(), g_free() when done.
 * Only decrypt authenticated data, as the padding check is not done in constant time.
 */
int lurch_om2_aes_encrypt(const uint8_t * key_p, const uint8_t * iv_p,
                          const uint8_t * in_p, size_t in_len,
                          uint8_t ** out_pp, size_t * out_len_p);
int lurch_om2_aes_decrypt(const uint8_t * key_p, const uint8_t * iv_p,
                          const uint8_t * in_p, size_t in_len,
                          uint8_t ** out_pp, size_t * out_len_p);

/** Generates a Curve25519 key pair. */
int lurch_om2_x25519_generate(lurch_om2_keypair * kp_p);

/** X25519. Fails if the result is all zero, i.e. the public key has a low order. */
int lurch_om2_x25519(const uint8_t * priv_p, const uint8_t * pub_p, uint8_t * out_p);

/**
 * The birational map between Ed25519 and Curve25519 public keys, see RFC 7748.
 * A Curve25519 public key does not determine the sign, so converted keys always have the sign bit cleared, as
 * expected by XEdDSA.
 */
int lurch_om2_ed_to_curve(const uint8_t * ed_p, uint8_t * curve_p);
int lurch_om2_curve_to_ed(const uint8_t * curve_p, uint8_t * ed_p);

/**
 * Signs using a Curve25519 private key, as lurch has its identity key from libsignal.
 * The signature is a valid RFC 8032 one for lurch_om2_curve_to_ed() of the public key.
 *
 * This is the actual XEdDSA, curve_calculate_signature() from libsignal is not suitable: it stores the sign of the
 * Edwards key in the signature, so about half of its signatures are invalid for anybody who expects RFC 8032.
 *
 * @param sig_p Will contain the signature, must have space for LURCH_OM2_SIG_LEN bytes.
 */
int lurch_om2_xeddsa_sign(const uint8_t * priv_p, const uint8_t * msg_p, size_t msg_len, uint8_t * sig_p);

/** Verifies a signature as defined by RFC 8032. @return 0 if and only if the signature is valid. */
int lurch_om2_ed_verify(const uint8_t * ed_p, const uint8_t * msg_p, size_t msg_len, const uint8_t * sig_p);
