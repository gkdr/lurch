#include <string.h>

#include <glib.h>

#include "lurch_om2_session.h"

#define SERIALIZED_VERSION 1
#define DERIVED_LEN 80
#define ROOT_DERIVED_LEN (LURCH_OM2_KEY_LEN * 2)
#define AD_LEN (LURCH_OM2_KEY_LEN * 2)

// protobuf: (field number << 3) | wire type, with 0 being a varint and 2 being length-delimited
#define PB_VARINT 0
#define PB_BYTES  2

typedef struct {
  uint8_t dh[LURCH_OM2_KEY_LEN];
  uint32_t n;
  uint8_t mk[LURCH_OM2_KEY_LEN];
} skipped_key;

struct lurch_om2_session {
  uint8_t rk[LURCH_OM2_KEY_LEN];
  lurch_om2_keypair dhs;
  uint8_t dhr[LURCH_OM2_KEY_LEN];
  uint8_t prev_dhr[LURCH_OM2_KEY_LEN]; // for recognizing messages of the last chain which were received already
  uint8_t cks[LURCH_OM2_KEY_LEN];
  uint8_t ckr[LURCH_OM2_KEY_LEN];
  uint32_t has_dhr;
  uint32_t has_cks;
  uint32_t has_ckr;
  uint32_t ns;
  uint32_t nr;
  uint32_t pn;
  uint8_t ad[AD_LEN];
  uint8_t remote_ik[LURCH_OM2_KEY_LEN];

  // what is needed for sending the OMEMOKeyExchange until something is received
  uint32_t kex_pending;
  uint32_t kex_pk_id;
  uint32_t kex_spk_id;
  uint8_t kex_ik[LURCH_OM2_KEY_LEN];
  uint8_t kex_ek[LURCH_OM2_KEY_LEN];

  // the other side's ephemeral key if this session was started passively
  uint32_t has_remote_ek;
  uint8_t remote_ek[LURCH_OM2_KEY_LEN];

  // whether a heartbeat was already requested for the current dhr
  uint32_t heartbeat_done;

  uint32_t skipped_len;
  skipped_key * skipped_p; // oldest first
};

typedef struct {
  uint32_t n;
  uint32_t pn;
  const uint8_t * dh_p;
  const uint8_t * ct_p;
  size_t ct_len;
} parsed_message;

static void pb_put_varint(GByteArray * out_p, uint64_t value) {
  while (value >= 0x80) {
    uint8_t byte = (uint8_t) (value & 0x7F) | 0x80;
    g_byte_array_append(out_p, &byte, 1);
    value >>= 7;
  }
  uint8_t byte = (uint8_t) value;
  g_byte_array_append(out_p, &byte, 1);
}

static void pb_put_uint32(GByteArray * out_p, uint32_t field, uint32_t value) {
  pb_put_varint(out_p, (field << 3) | PB_VARINT);
  pb_put_varint(out_p, value);
}

static void pb_put_bytes(GByteArray * out_p, uint32_t field, const uint8_t * data_p, size_t len) {
  pb_put_varint(out_p, (field << 3) | PB_BYTES);
  pb_put_varint(out_p, len);
  if (len) {
    g_byte_array_append(out_p, data_p, len);
  }
}

static int pb_get_varint(const uint8_t ** cur_pp, const uint8_t * end_p, uint64_t * value_p) {
  uint64_t value = 0;

  for (int shift = 0; shift < 64; shift += 7) {
    if (*cur_pp >= end_p) {
      return -1;
    }
    uint8_t byte = *(*cur_pp)++;
    value |= (uint64_t) (byte & 0x7F) << shift;
    if (!(byte & 0x80)) {
      *value_p = value;
      return 0;
    }
  }

  return -1;
}

/**
 * Reads the next field.
 *
 * @return 1 if there is one, 0 at the end, negative if malformed.
 */
static int pb_next(const uint8_t ** cur_pp, const uint8_t * end_p, uint32_t * field_p, uint64_t * value_p, const uint8_t ** data_pp) {
  uint64_t tag = 0;
  uint64_t len = 0;

  if (*cur_pp == end_p) {
    return 0;
  }

  if (pb_get_varint(cur_pp, end_p, &tag) || (tag >> 3) > UINT32_MAX) {
    return -1;
  }

  *field_p = (uint32_t) (tag >> 3);
  *data_pp = (void *) 0;

  switch (tag & 0x7) {
    case PB_VARINT:
      return pb_get_varint(cur_pp, end_p, value_p) ? -1 : 1;
    case PB_BYTES:
      if (pb_get_varint(cur_pp, end_p, &len) || len > (uint64_t) (end_p - *cur_pp)) {
        return -1;
      }
      *data_pp = *cur_pp;
      *value_p = len;
      *cur_pp += len;
      return 1;
    default:
      // none of the structures use anything else
      return -1;
  }
}

static int message_parse(const uint8_t * in_p, size_t in_len, parsed_message * msg_p) {
  const uint8_t * cur_p = in_p;
  const uint8_t * end_p = in_p + in_len;
  const uint8_t * data_p = (void *) 0;
  uint32_t field = 0;
  uint64_t value = 0;
  int ret_val = 0;
  int seen = 0;

  memset(msg_p, 0, sizeof(*msg_p));

  while ((ret_val = pb_next(&cur_p, end_p, &field, &value, &data_p)) == 1) {
    if (field == 1 && !data_p && value <= UINT32_MAX) {
      msg_p->n = (uint32_t) value;
      seen |= 1;
    } else if (field == 2 && !data_p && value <= UINT32_MAX) {
      msg_p->pn = (uint32_t) value;
      seen |= 2;
    } else if (field == 3 && data_p && value == LURCH_OM2_KEY_LEN) {
      msg_p->dh_p = data_p;
      seen |= 4;
    } else if (field == 4 && data_p) {
      msg_p->ct_p = data_p;
      msg_p->ct_len = (size_t) value;
      seen |= 8;
    } else {
      return LURCH_OM2_ERR;
    }
  }

  return (ret_val == 0 && seen == 15) ? 0 : LURCH_OM2_ERR;
}

static int authenticated_parse(const uint8_t * in_p, size_t in_len, const uint8_t ** mac_pp, const uint8_t ** msg_pp, size_t * msg_len_p) {
  const uint8_t * cur_p = in_p;
  const uint8_t * end_p = in_p + in_len;
  const uint8_t * data_p = (void *) 0;
  uint32_t field = 0;
  uint64_t value = 0;
  int ret_val = 0;

  *mac_pp = (void *) 0;
  *msg_pp = (void *) 0;

  while ((ret_val = pb_next(&cur_p, end_p, &field, &value, &data_p)) == 1) {
    if (field == 1 && data_p && value == LURCH_OM2_TAG_LEN) {
      *mac_pp = data_p;
    } else if (field == 2 && data_p) {
      *msg_pp = data_p;
      *msg_len_p = (size_t) value;
    } else {
      return LURCH_OM2_ERR;
    }
  }

  return (ret_val == 0 && *mac_pp && *msg_pp) ? 0 : LURCH_OM2_ERR;
}

int lurch_om2_key_exchange_parse(const uint8_t * in_p, size_t in_len, lurch_om2_key_exchange * kex_p) {
  const uint8_t * cur_p = in_p;
  const uint8_t * end_p = in_p + in_len;
  const uint8_t * data_p = (void *) 0;
  uint32_t field = 0;
  uint64_t value = 0;
  int ret_val = 0;
  int seen = 0;

  memset(kex_p, 0, sizeof(*kex_p));

  while ((ret_val = pb_next(&cur_p, end_p, &field, &value, &data_p)) == 1) {
    if (field == 1 && !data_p && value <= UINT32_MAX) {
      kex_p->pk_id = (uint32_t) value;
      seen |= 1;
    } else if (field == 2 && !data_p && value <= UINT32_MAX) {
      kex_p->spk_id = (uint32_t) value;
      seen |= 2;
    } else if (field == 3 && data_p && value == LURCH_OM2_KEY_LEN) {
      memcpy(kex_p->ik_ed, data_p, LURCH_OM2_KEY_LEN);
      seen |= 4;
    } else if (field == 4 && data_p && value == LURCH_OM2_KEY_LEN) {
      memcpy(kex_p->ek, data_p, LURCH_OM2_KEY_LEN);
      seen |= 8;
    } else if (field == 5 && data_p) {
      kex_p->msg_p = data_p;
      kex_p->msg_len = (size_t) value;
      seen |= 16;
    } else {
      return LURCH_OM2_ERR;
    }
  }

  return (ret_val == 0 && seen == 31) ? 0 : LURCH_OM2_ERR;
}

/** KDF_RK: the first half of the output is the new root key, the second one a new chain key. */
static int kdf_rk(uint8_t * rk_p, const uint8_t * dh_out_p, uint8_t * ck_p) {
  uint8_t out[ROOT_DERIVED_LEN];
  int ret_val = lurch_om2_hkdf(rk_p, LURCH_OM2_KEY_LEN, dh_out_p, LURCH_OM2_KEY_LEN, LURCH_OM2_INFO_ROOT, out, sizeof(out));

  if (!ret_val) {
    memcpy(rk_p, out, LURCH_OM2_KEY_LEN);
    memcpy(ck_p, out + LURCH_OM2_KEY_LEN, LURCH_OM2_KEY_LEN);
  }

  lurch_om2_wipe(out, sizeof(out));
  return ret_val;
}

/** KDF_CK: gives the next message key and advances the chain. */
static int kdf_ck(uint8_t * ck_p, uint8_t * mk_p) {
  static const uint8_t mk_input = 0x01;
  static const uint8_t ck_input = 0x02;
  uint8_t next_ck[LURCH_OM2_KEY_LEN];

  if (lurch_om2_hmac(ck_p, LURCH_OM2_KEY_LEN, &mk_input, 1, mk_p)
      || lurch_om2_hmac(ck_p, LURCH_OM2_KEY_LEN, &ck_input, 1, next_ck)) {
    return LURCH_OM2_ERR;
  }

  memcpy(ck_p, next_ck, LURCH_OM2_KEY_LEN);
  lurch_om2_wipe(next_ck, sizeof(next_ck));
  return 0;
}

/** Splits the key material into encryption key, authentication key and IV. */
static int derive_keys(const uint8_t * key_p, const char * info, uint8_t * derived_p) {
  return lurch_om2_hkdf((void *) 0, 0, key_p, LURCH_OM2_KEY_LEN, info, derived_p, DERIVED_LEN);
}

/** The X3DH shared secret: HKDF(F || DH1 || DH2 || DH3 || DH4), with F being 32 * 0xFF. */
static int x3dh_secret(const uint8_t dhs[4][LURCH_OM2_KEY_LEN], uint8_t * sk_p) {
  uint8_t ikm[LURCH_OM2_KEY_LEN * 5];
  int ret_val = 0;

  memset(ikm, 0xFF, LURCH_OM2_KEY_LEN);
  memcpy(ikm + LURCH_OM2_KEY_LEN, dhs, LURCH_OM2_KEY_LEN * 4);

  ret_val = lurch_om2_hkdf((void *) 0, 0, ikm, sizeof(ikm), LURCH_OM2_INFO_X3DH, sk_p, LURCH_OM2_KEY_LEN);

  lurch_om2_wipe(ikm, sizeof(ikm));
  return ret_val;
}

int lurch_om2_session_create_active(const lurch_om2_keypair * own_ik_p, const lurch_om2_bundle * bundle_p, lurch_om2_session ** session_pp) {
  int ret_val = LURCH_OM2_ERR;
  lurch_om2_session * s_p = (void *) 0;
  lurch_om2_keypair ek;
  uint8_t own_ik_ed[LURCH_OM2_KEY_LEN];
  uint8_t remote_ik_curve[LURCH_OM2_KEY_LEN];
  uint8_t dhs[4][LURCH_OM2_KEY_LEN];
  uint8_t sk[LURCH_OM2_KEY_LEN];
  uint8_t dh_out[LURCH_OM2_KEY_LEN];

  if (lurch_om2_ed_verify(bundle_p->ik_ed, bundle_p->spk, LURCH_OM2_KEY_LEN, bundle_p->spk_sig)) {
    return LURCH_OM2_ERR_AUTH;
  }

  if (lurch_om2_x25519_generate(&ek)
      || lurch_om2_curve_to_ed(own_ik_p->pub, own_ik_ed)
      || lurch_om2_ed_to_curve(bundle_p->ik_ed, remote_ik_curve)
      || lurch_om2_x25519(own_ik_p->priv, bundle_p->spk, dhs[0])
      || lurch_om2_x25519(ek.priv, remote_ik_curve, dhs[1])
      || lurch_om2_x25519(ek.priv, bundle_p->spk, dhs[2])
      || lurch_om2_x25519(ek.priv, bundle_p->pk, dhs[3])
      || x3dh_secret((const uint8_t (*)[LURCH_OM2_KEY_LEN]) dhs, sk)) {
    goto cleanup;
  }

  s_p = g_new0(lurch_om2_session, 1);
  memcpy(s_p->rk, sk, LURCH_OM2_KEY_LEN);
  memcpy(s_p->ad, own_ik_ed, LURCH_OM2_KEY_LEN);
  memcpy(s_p->ad + LURCH_OM2_KEY_LEN, bundle_p->ik_ed, LURCH_OM2_KEY_LEN);
  memcpy(s_p->remote_ik, bundle_p->ik_ed, LURCH_OM2_KEY_LEN);

  s_p->kex_pending = 1;
  s_p->kex_pk_id = bundle_p->pk_id;
  s_p->kex_spk_id = bundle_p->spk_id;
  memcpy(s_p->kex_ik, own_ik_ed, LURCH_OM2_KEY_LEN);
  memcpy(s_p->kex_ek, ek.pub, LURCH_OM2_KEY_LEN);

  // the other side's first ratchet key is the signed PreKey
  memcpy(s_p->dhr, bundle_p->spk, LURCH_OM2_KEY_LEN);
  s_p->has_dhr = 1;

  if (lurch_om2_x25519_generate(&s_p->dhs)
      || lurch_om2_x25519(s_p->dhs.priv, s_p->dhr, dh_out)
      || kdf_rk(s_p->rk, dh_out, s_p->cks)) {
    goto cleanup;
  }
  s_p->has_cks = 1;

  *session_pp = s_p;
  s_p = (void *) 0;
  ret_val = 0;

cleanup:
  lurch_om2_session_destroy(s_p);
  lurch_om2_wipe(&ek, sizeof(ek));
  lurch_om2_wipe(dhs, sizeof(dhs));
  lurch_om2_wipe(sk, sizeof(sk));
  lurch_om2_wipe(dh_out, sizeof(dh_out));
  return ret_val;
}

int lurch_om2_session_create_passive(const lurch_om2_keypair * own_ik_p,
                                     const lurch_om2_keypair * own_spk_p,
                                     const lurch_om2_keypair * own_pk_p,
                                     const lurch_om2_key_exchange * kex_p,
                                     lurch_om2_session ** session_pp) {
  int ret_val = LURCH_OM2_ERR;
  lurch_om2_session * s_p = (void *) 0;
  uint8_t own_ik_ed[LURCH_OM2_KEY_LEN];
  uint8_t remote_ik_curve[LURCH_OM2_KEY_LEN];
  uint8_t dhs[4][LURCH_OM2_KEY_LEN];
  uint8_t sk[LURCH_OM2_KEY_LEN];

  if (lurch_om2_curve_to_ed(own_ik_p->pub, own_ik_ed)
      || lurch_om2_ed_to_curve(kex_p->ik_ed, remote_ik_curve)
      || lurch_om2_x25519(own_spk_p->priv, remote_ik_curve, dhs[0])
      || lurch_om2_x25519(own_ik_p->priv, kex_p->ek, dhs[1])
      || lurch_om2_x25519(own_spk_p->priv, kex_p->ek, dhs[2])
      || lurch_om2_x25519(own_pk_p->priv, kex_p->ek, dhs[3])
      || x3dh_secret((const uint8_t (*)[LURCH_OM2_KEY_LEN]) dhs, sk)) {
    goto cleanup;
  }

  s_p = g_new0(lurch_om2_session, 1);
  memcpy(s_p->rk, sk, LURCH_OM2_KEY_LEN);
  memcpy(s_p->ad, kex_p->ik_ed, LURCH_OM2_KEY_LEN);
  memcpy(s_p->ad + LURCH_OM2_KEY_LEN, own_ik_ed, LURCH_OM2_KEY_LEN);
  memcpy(s_p->remote_ik, kex_p->ik_ed, LURCH_OM2_KEY_LEN);
  memcpy(&s_p->dhs, own_spk_p, sizeof(s_p->dhs));
  memcpy(s_p->remote_ek, kex_p->ek, LURCH_OM2_KEY_LEN);
  s_p->has_remote_ek = 1;

  *session_pp = s_p;
  ret_val = 0;

cleanup:
  lurch_om2_wipe(dhs, sizeof(dhs));
  lurch_om2_wipe(sk, sizeof(sk));
  return ret_val;
}

void lurch_om2_session_destroy(lurch_om2_session * session_p) {
  if (!session_p) {
    return;
  }

  if (session_p->skipped_p) {
    lurch_om2_wipe(session_p->skipped_p, session_p->skipped_len * sizeof(skipped_key));
    g_free(session_p->skipped_p);
  }

  lurch_om2_wipe(session_p, sizeof(*session_p));
  g_free(session_p);
}

int lurch_om2_session_serialize(const lurch_om2_session * session_p, uint8_t ** out_pp, size_t * out_len_p) {
  // Just the fields in memory, as this does not leave this device. skipped_p is at the end of the struct.
  size_t fixed_len = offsetof(lurch_om2_session, skipped_p);
  size_t skipped_len = session_p->skipped_len * sizeof(skipped_key);
  uint8_t * out_p = g_malloc(1 + fixed_len + skipped_len);

  out_p[0] = SERIALIZED_VERSION;
  memcpy(out_p + 1, session_p, fixed_len);
  if (skipped_len) {
    memcpy(out_p + 1 + fixed_len, session_p->skipped_p, skipped_len);
  }

  *out_pp = out_p;
  *out_len_p = 1 + fixed_len + skipped_len;
  return 0;
}

int lurch_om2_session_deserialize(const uint8_t * in_p, size_t in_len, lurch_om2_session ** session_pp) {
  size_t fixed_len = offsetof(lurch_om2_session, skipped_p);
  lurch_om2_session * s_p = (void *) 0;

  if (in_len < 1 + fixed_len || in_p[0] != SERIALIZED_VERSION) {
    return LURCH_OM2_ERR;
  }

  s_p = g_new0(lurch_om2_session, 1);
  memcpy(s_p, in_p + 1, fixed_len);

  if (s_p->skipped_len > LURCH_OM2_MAX_SKIP || in_len != 1 + fixed_len + s_p->skipped_len * sizeof(skipped_key)) {
    s_p->skipped_len = 0;
    lurch_om2_session_destroy(s_p);
    return LURCH_OM2_ERR;
  }

  if (s_p->skipped_len) {
    s_p->skipped_p = g_malloc(s_p->skipped_len * sizeof(skipped_key));
    memcpy(s_p->skipped_p, in_p + 1 + fixed_len, s_p->skipped_len * sizeof(skipped_key));
  }

  *session_pp = s_p;
  return 0;
}

int lurch_om2_session_has_remote_ek(const lurch_om2_session * session_p, const uint8_t * ek_p) {
  return session_p->has_remote_ek && lurch_om2_equal(session_p->remote_ek, ek_p, LURCH_OM2_KEY_LEN);
}

const uint8_t * lurch_om2_session_get_remote_ik(const lurch_om2_session * session_p) {
  return session_p->remote_ik;
}

/**
 * The AEAD of the ratchet, encrypting a key.
 * The tag covers the associated data and the whole serialized message, including the header.
 */
static int aead_encrypt(lurch_om2_session * s_p, const uint8_t * mk_p, const uint8_t * plain_p, size_t plain_len, GByteArray * out_p) {
  int ret_val = LURCH_OM2_ERR;
  uint8_t derived[DERIVED_LEN];
  uint8_t tag[LURCH_OM2_KEY_LEN];
  uint8_t * ct_p = (void *) 0;
  size_t ct_len = 0;
  GByteArray * message_p = g_byte_array_new();
  GByteArray * mac_input_p = g_byte_array_new();

  if (derive_keys(mk_p, LURCH_OM2_INFO_MESSAGE, derived)
      || lurch_om2_aes_encrypt(derived, derived + 2 * LURCH_OM2_KEY_LEN, plain_p, plain_len, &ct_p, &ct_len)) {
    goto cleanup;
  }

  pb_put_uint32(message_p, 1, s_p->ns);
  pb_put_uint32(message_p, 2, s_p->pn);
  pb_put_bytes(message_p, 3, s_p->dhs.pub, LURCH_OM2_KEY_LEN);
  pb_put_bytes(message_p, 4, ct_p, ct_len);

  g_byte_array_append(mac_input_p, s_p->ad, AD_LEN);
  g_byte_array_append(mac_input_p, message_p->data, message_p->len);

  if (lurch_om2_hmac(derived + LURCH_OM2_KEY_LEN, LURCH_OM2_KEY_LEN, mac_input_p->data, mac_input_p->len, tag)) {
    goto cleanup;
  }

  pb_put_bytes(out_p, 1, tag, LURCH_OM2_TAG_LEN);
  pb_put_bytes(out_p, 2, message_p->data, message_p->len);
  ret_val = 0;

cleanup:
  lurch_om2_wipe(derived, sizeof(derived));
  g_free(ct_p);
  g_byte_array_free(message_p, TRUE);
  g_byte_array_free(mac_input_p, TRUE);
  return ret_val;
}

int lurch_om2_session_encrypt(lurch_om2_session * session_p, const uint8_t * plain_p, size_t plain_len, uint8_t ** out_pp, size_t * out_len_p, int * is_kex_p) {
  int ret_val = LURCH_OM2_ERR;
  uint8_t mk[LURCH_OM2_KEY_LEN];
  GByteArray * auth_p = g_byte_array_new();
  GByteArray * out_p = (void *) 0;

  // A passively started session has no sending chain until the first message was decrypted.
  if (!session_p->has_cks) {
    goto cleanup;
  }

  if (kdf_ck(session_p->cks, mk) || aead_encrypt(session_p, mk, plain_p, plain_len, auth_p)) {
    goto cleanup;
  }
  session_p->ns++;

  if (session_p->kex_pending) {
    out_p = g_byte_array_new();
    pb_put_uint32(out_p, 1, session_p->kex_pk_id);
    pb_put_uint32(out_p, 2, session_p->kex_spk_id);
    pb_put_bytes(out_p, 3, session_p->kex_ik, LURCH_OM2_KEY_LEN);
    pb_put_bytes(out_p, 4, session_p->kex_ek, LURCH_OM2_KEY_LEN);
    pb_put_bytes(out_p, 5, auth_p->data, auth_p->len);
    *out_len_p = out_p->len;
    *out_pp = g_byte_array_free(out_p, FALSE);
    *is_kex_p = 1;
  } else {
    *out_len_p = auth_p->len;
    *out_pp = g_byte_array_free(auth_p, FALSE);
    auth_p = (void *) 0;
    *is_kex_p = 0;
  }

  ret_val = 0;

cleanup:
  lurch_om2_wipe(mk, sizeof(mk));
  if (auth_p) {
    g_byte_array_free(auth_p, TRUE);
  }
  return ret_val;
}

static int aead_decrypt(const lurch_om2_session * s_p, const uint8_t * mk_p, const uint8_t * mac_p, const uint8_t * msg_p, size_t msg_len, const parsed_message * parsed_p, uint8_t ** out_pp, size_t * out_len_p) {
  int ret_val = LURCH_OM2_ERR_AUTH;
  uint8_t derived[DERIVED_LEN];
  uint8_t tag[LURCH_OM2_KEY_LEN];
  GByteArray * mac_input_p = g_byte_array_new();

  if (derive_keys(mk_p, LURCH_OM2_INFO_MESSAGE, derived)) {
    goto cleanup;
  }

  g_byte_array_append(mac_input_p, s_p->ad, AD_LEN);
  g_byte_array_append(mac_input_p, msg_p, msg_len);

  if (lurch_om2_hmac(derived + LURCH_OM2_KEY_LEN, LURCH_OM2_KEY_LEN, mac_input_p->data, mac_input_p->len, tag)
      || !lurch_om2_equal(tag, mac_p, LURCH_OM2_TAG_LEN)) {
    goto cleanup;
  }

  if (lurch_om2_aes_decrypt(derived, derived + 2 * LURCH_OM2_KEY_LEN, parsed_p->ct_p, parsed_p->ct_len, out_pp, out_len_p)) {
    goto cleanup;
  }

  ret_val = 0;

cleanup:
  lurch_om2_wipe(derived, sizeof(derived));
  g_byte_array_free(mac_input_p, TRUE);
  return ret_val;
}

/** Stores a key for a message that did not arrive yet. If there are too many, the oldest ones are discarded. */
static void skipped_add(lurch_om2_session * s_p, const uint8_t * dh_p, uint32_t n, const uint8_t * mk_p) {
  skipped_key * key_p = (void *) 0;

  if (s_p->skipped_len == LURCH_OM2_MAX_SKIP) {
    lurch_om2_wipe(s_p->skipped_p, sizeof(skipped_key));
    memmove(s_p->skipped_p, s_p->skipped_p + 1, (LURCH_OM2_MAX_SKIP - 1) * sizeof(skipped_key));
    s_p->skipped_len--;
  } else {
    s_p->skipped_p = g_realloc(s_p->skipped_p, (s_p->skipped_len + 1) * sizeof(skipped_key));
  }

  key_p = &s_p->skipped_p[s_p->skipped_len++];
  memcpy(key_p->dh, dh_p, LURCH_OM2_KEY_LEN);
  key_p->n = n;
  memcpy(key_p->mk, mk_p, LURCH_OM2_KEY_LEN);
}

/** Advances the receiving chain up to this message number, keeping the keys of everything on the way. */
static int skip_until(lurch_om2_session * s_p, uint32_t until) {
  uint8_t mk[LURCH_OM2_KEY_LEN];

  if (!s_p->has_ckr) {
    return until == 0 ? 0 : LURCH_OM2_ERR;
  }

  if (until > s_p->nr && until - s_p->nr > LURCH_OM2_MAX_SKIP) {
    return LURCH_OM2_ERR_TOO_MANY_SKIP;
  }

  while (s_p->nr < until) {
    if (kdf_ck(s_p->ckr, mk)) {
      lurch_om2_wipe(mk, sizeof(mk));
      return LURCH_OM2_ERR;
    }
    skipped_add(s_p, s_p->dhr, s_p->nr, mk);
    s_p->nr++;
  }

  lurch_om2_wipe(mk, sizeof(mk));
  return 0;
}

static int dh_ratchet(lurch_om2_session * s_p, const uint8_t * dh_p) {
  uint8_t dh_out[LURCH_OM2_KEY_LEN];
  int ret_val = LURCH_OM2_ERR;

  s_p->pn = s_p->ns;
  s_p->ns = 0;
  s_p->nr = 0;
  memcpy(s_p->prev_dhr, s_p->dhr, LURCH_OM2_KEY_LEN);
  memcpy(s_p->dhr, dh_p, LURCH_OM2_KEY_LEN);
  s_p->has_dhr = 1;
  s_p->heartbeat_done = 0;

  if (lurch_om2_x25519(s_p->dhs.priv, s_p->dhr, dh_out) || kdf_rk(s_p->rk, dh_out, s_p->ckr)) {
    goto cleanup;
  }
  s_p->has_ckr = 1;

  if (lurch_om2_x25519_generate(&s_p->dhs)
      || lurch_om2_x25519(s_p->dhs.priv, s_p->dhr, dh_out)
      || kdf_rk(s_p->rk, dh_out, s_p->cks)) {
    goto cleanup;
  }
  s_p->has_cks = 1;

  ret_val = 0;

cleanup:
  lurch_om2_wipe(dh_out, sizeof(dh_out));
  return ret_val;
}

int lurch_om2_session_decrypt(lurch_om2_session * session_p, const uint8_t * msg_p, size_t msg_len, uint8_t ** out_pp, size_t * out_len_p, int * needs_heartbeat_p) {
  const uint8_t * mac_p = (void *) 0;
  const uint8_t * inner_p = (void *) 0;
  size_t inner_len = 0;
  parsed_message parsed;
  uint8_t mk[LURCH_OM2_KEY_LEN];
  int ret_val = 0;

  *needs_heartbeat_p = 0;

  if (authenticated_parse(msg_p, msg_len, &mac_p, &inner_p, &inner_len) || message_parse(inner_p, inner_len, &parsed)) {
    return LURCH_OM2_ERR;
  }

  for (uint32_t i = 0; i < session_p->skipped_len; i++) {
    skipped_key * key_p = &session_p->skipped_p[i];

    if (key_p->n == parsed.n && lurch_om2_equal(key_p->dh, parsed.dh_p, LURCH_OM2_KEY_LEN)) {
      ret_val = aead_decrypt(session_p, key_p->mk, mac_p, inner_p, inner_len, &parsed, out_pp, out_len_p);
      if (!ret_val) {
        lurch_om2_wipe(key_p, sizeof(*key_p));
        memmove(key_p, key_p + 1, (session_p->skipped_len - i - 1) * sizeof(skipped_key));
        session_p->skipped_len--;
        session_p->kex_pending = 0;
      }
      return ret_val;
    }
  }

  // No key left for a message of the previous chain. This must not cause a ratchet step, it would break the session.
  if (session_p->has_ckr && lurch_om2_equal(session_p->prev_dhr, parsed.dh_p, LURCH_OM2_KEY_LEN)) {
    return LURCH_OM2_ERR_DUPLICATE;
  }

  if (!session_p->has_dhr || !lurch_om2_equal(session_p->dhr, parsed.dh_p, LURCH_OM2_KEY_LEN) || !session_p->has_ckr) {
    // The message of a new chain, which also is the only way to start the receiving chain.
    if (session_p->has_dhr && session_p->has_ckr) {
      ret_val = skip_until(session_p, parsed.pn);
      if (ret_val) {
        return ret_val;
      }
    }

    if (parsed.n > LURCH_OM2_MAX_SKIP) {
      return LURCH_OM2_ERR_TOO_MANY_SKIP;
    }

    if (dh_ratchet(session_p, parsed.dh_p)) {
      return LURCH_OM2_ERR;
    }
  } else if (parsed.n < session_p->nr) {
    // There is no key left for it, so it was already received. Forged messages end up here as well, which is fine as
    // they just get ignored.
    return LURCH_OM2_ERR_DUPLICATE;
  }

  ret_val = skip_until(session_p, parsed.n);
  if (ret_val) {
    return ret_val;
  }

  if (kdf_ck(session_p->ckr, mk)) {
    return LURCH_OM2_ERR;
  }
  session_p->nr++;

  ret_val = aead_decrypt(session_p, mk, mac_p, inner_p, inner_len, &parsed, out_pp, out_len_p);
  lurch_om2_wipe(mk, sizeof(mk));
  if (ret_val) {
    return ret_val;
  }

  session_p->kex_pending = 0;

  if (parsed.n >= LURCH_OM2_HEARTBEAT_COUNTER && !session_p->heartbeat_done) {
    session_p->heartbeat_done = 1;
    *needs_heartbeat_p = 1;
  }

  return 0;
}

int lurch_om2_payload_encrypt(const uint8_t * plain_p, size_t plain_len, uint8_t * key_and_tag_p, uint8_t ** out_pp, size_t * out_len_p) {
  int ret_val = LURCH_OM2_ERR;
  uint8_t key[LURCH_OM2_KEY_LEN];
  uint8_t derived[DERIVED_LEN];
  uint8_t tag[LURCH_OM2_KEY_LEN];
  uint8_t * ct_p = (void *) 0;
  size_t ct_len = 0;

  lurch_om2_random(key, sizeof(key));

  if (derive_keys(key, LURCH_OM2_INFO_PAYLOAD, derived)
      || lurch_om2_aes_encrypt(derived, derived + 2 * LURCH_OM2_KEY_LEN, plain_p, plain_len, &ct_p, &ct_len)
      || lurch_om2_hmac(derived + LURCH_OM2_KEY_LEN, LURCH_OM2_KEY_LEN, ct_p, ct_len, tag)) {
    g_free(ct_p);
    goto cleanup;
  }

  memcpy(key_and_tag_p, key, LURCH_OM2_KEY_LEN);
  memcpy(key_and_tag_p + LURCH_OM2_KEY_LEN, tag, LURCH_OM2_TAG_LEN);
  *out_pp = ct_p;
  *out_len_p = ct_len;
  ret_val = 0;

cleanup:
  lurch_om2_wipe(key, sizeof(key));
  lurch_om2_wipe(derived, sizeof(derived));
  return ret_val;
}

int lurch_om2_payload_decrypt(const uint8_t * key_and_tag_p, const uint8_t * in_p, size_t in_len, uint8_t ** out_pp, size_t * out_len_p) {
  int ret_val = LURCH_OM2_ERR_AUTH;
  uint8_t derived[DERIVED_LEN];
  uint8_t tag[LURCH_OM2_KEY_LEN];

  if (derive_keys(key_and_tag_p, LURCH_OM2_INFO_PAYLOAD, derived)
      || lurch_om2_hmac(derived + LURCH_OM2_KEY_LEN, LURCH_OM2_KEY_LEN, in_p, in_len, tag)
      || !lurch_om2_equal(tag, key_and_tag_p + LURCH_OM2_KEY_LEN, LURCH_OM2_TAG_LEN)) {
    goto cleanup;
  }

  if (!lurch_om2_aes_decrypt(derived, derived + 2 * LURCH_OM2_KEY_LEN, in_p, in_len, out_pp, out_len_p)) {
    ret_val = 0;
  }

cleanup:
  lurch_om2_wipe(derived, sizeof(derived));
  return ret_val;
}
