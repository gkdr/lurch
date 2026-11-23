#include <string.h>

#include <gcrypt.h>
#include <glib.h>

#include "lurch_om2_crypto.h"

#define HASH_LEN 32
#define AES_BLOCK_LEN 16

// 2^255 - 19
#define P25519_HEX "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"

int lurch_om2_hmac(const uint8_t * key_p, size_t key_len, const uint8_t * data_p, size_t data_len, uint8_t * out_p) {
  gcry_mac_hd_t hd = (void *) 0;
  size_t out_len = HASH_LEN;
  int ret_val = -1;

  if (gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, GCRY_MAC_FLAG_SECURE, (void *) 0)) {
    return -1;
  }

  if (!gcry_mac_setkey(hd, key_p, key_len)
      && !gcry_mac_write(hd, data_p, data_len)
      && !gcry_mac_read(hd, out_p, &out_len)
      && out_len == HASH_LEN) {
    ret_val = 0;
  }

  gcry_mac_close(hd);
  return ret_val;
}

int lurch_om2_hkdf(const uint8_t * salt_p, size_t salt_len,
                   const uint8_t * ikm_p, size_t ikm_len,
                   const char * info,
                   uint8_t * out_p, size_t out_len) {
  uint8_t prk[HASH_LEN];
  uint8_t t[HASH_LEN];
  uint8_t zero_salt[HASH_LEN] = {0};
  size_t info_len = strlen(info);
  size_t input_len = 0;
  size_t done = 0;
  uint8_t counter = 1;
  uint8_t * input_p = (void *) 0;
  int ret_val = -1;

  if (out_len > 255 * HASH_LEN) {
    return -1;
  }

  if (!salt_p) {
    salt_p = zero_salt;
    salt_len = sizeof(zero_salt);
  }

  if (lurch_om2_hmac(salt_p, salt_len, ikm_p, ikm_len, prk)) {
    goto cleanup;
  }

  input_p = g_malloc(HASH_LEN + info_len + 1);

  while (done < out_len) {
    size_t todo = MIN(out_len - done, HASH_LEN);

    // T(n) = HMAC(PRK, T(n-1) | info | n), with an empty T(0)
    input_len = 0;
    if (done) {
      memcpy(input_p, t, HASH_LEN);
      input_len = HASH_LEN;
    }
    memcpy(input_p + input_len, info, info_len);
    input_len += info_len;
    input_p[input_len++] = counter++;

    if (lurch_om2_hmac(prk, HASH_LEN, input_p, input_len, t)) {
      goto cleanup;
    }

    memcpy(out_p + done, t, todo);
    done += todo;
  }

  ret_val = 0;

cleanup:
  lurch_om2_wipe(prk, sizeof(prk));
  lurch_om2_wipe(t, sizeof(t));
  if (input_p) {
    lurch_om2_wipe(input_p, HASH_LEN + info_len + 1);
    g_free(input_p);
  }
  return ret_val;
}

void lurch_om2_random(uint8_t * out_p, size_t len) {
  gcry_randomize(out_p, len, GCRY_STRONG_RANDOM);
}

int lurch_om2_equal(const uint8_t * a_p, const uint8_t * b_p, size_t len) {
  volatile uint8_t diff = 0;

  for (size_t i = 0; i < len; i++) {
    diff |= a_p[i] ^ b_p[i];
  }

  return diff == 0;
}

void lurch_om2_wipe(void * p, size_t len) {
  volatile uint8_t * v_p = p;

  while (len--) {
    *v_p++ = 0;
  }
}

static int lurch_om2_aes_crypt(int encrypt, const uint8_t * key_p, const uint8_t * iv_p, const uint8_t * in_p, uint8_t * out_p, size_t len) {
  gcry_cipher_hd_t hd = (void *) 0;
  gcry_error_t err = 0;

  if (gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE)) {
    return -1;
  }

  err = gcry_cipher_setkey(hd, key_p, LURCH_OM2_KEY_LEN);
  if (!err) {
    err = gcry_cipher_setiv(hd, iv_p, LURCH_OM2_IV_LEN);
  }
  if (!err) {
    err = encrypt ? gcry_cipher_encrypt(hd, out_p, len, in_p, len) : gcry_cipher_decrypt(hd, out_p, len, in_p, len);
  }

  gcry_cipher_close(hd);
  return err ? -1 : 0;
}

int lurch_om2_aes_encrypt(const uint8_t * key_p, const uint8_t * iv_p,
                          const uint8_t * in_p, size_t in_len,
                          uint8_t ** out_pp, size_t * out_len_p) {
  size_t pad_len = AES_BLOCK_LEN - (in_len % AES_BLOCK_LEN);
  size_t len = in_len + pad_len;
  uint8_t * padded_p = g_malloc(len);
  uint8_t * out_p = g_malloc(len);
  int ret_val = 0;

  if (in_len) {
    memcpy(padded_p, in_p, in_len);
  }
  memset(padded_p + in_len, (int) pad_len, pad_len);

  ret_val = lurch_om2_aes_crypt(1, key_p, iv_p, padded_p, out_p, len);

  lurch_om2_wipe(padded_p, len);
  g_free(padded_p);

  if (ret_val) {
    g_free(out_p);
    return ret_val;
  }

  *out_pp = out_p;
  *out_len_p = len;
  return 0;
}

int lurch_om2_aes_decrypt(const uint8_t * key_p, const uint8_t * iv_p,
                          const uint8_t * in_p, size_t in_len,
                          uint8_t ** out_pp, size_t * out_len_p) {
  uint8_t * out_p = (void *) 0;
  size_t pad_len = 0;

  if (!in_len || in_len % AES_BLOCK_LEN) {
    return -1;
  }

  out_p = g_malloc(in_len);
  if (lurch_om2_aes_crypt(0, key_p, iv_p, in_p, out_p, in_len)) {
    goto fail;
  }

  pad_len = out_p[in_len - 1];
  if (!pad_len || pad_len > AES_BLOCK_LEN) {
    goto fail;
  }
  for (size_t i = 0; i < pad_len; i++) {
    if (out_p[in_len - 1 - i] != pad_len) {
      goto fail;
    }
  }

  *out_pp = out_p;
  *out_len_p = in_len - pad_len;
  return 0;

fail:
  lurch_om2_wipe(out_p, in_len);
  g_free(out_p);
  return -1;
}

int lurch_om2_x25519(const uint8_t * priv_p, const uint8_t * pub_p, uint8_t * out_p) {
  static const uint8_t zero[LURCH_OM2_KEY_LEN] = {0};
  uint8_t scalar[LURCH_OM2_KEY_LEN];
  uint8_t point[LURCH_OM2_KEY_LEN];
  gcry_error_t err = 0;

  memcpy(scalar, priv_p, sizeof(scalar));
  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;

  memcpy(point, pub_p, sizeof(point));
  point[31] &= 127;

  err = gcry_ecc_mul_point(GCRY_ECC_CURVE25519, out_p, scalar, point);
  lurch_om2_wipe(scalar, sizeof(scalar));

  if (err) {
    return -1;
  }

  return lurch_om2_equal(out_p, zero, LURCH_OM2_KEY_LEN) ? -1 : 0;
}

int lurch_om2_x25519_generate(lurch_om2_keypair * kp_p) {
  static const uint8_t base[LURCH_OM2_KEY_LEN] = {9};

  lurch_om2_random(kp_p->priv, LURCH_OM2_KEY_LEN);

  return lurch_om2_x25519(kp_p->priv, base, kp_p->pub);
}

/** Reads a little endian field element. */
static gcry_mpi_t lurch_om2_mpi_from_le(const uint8_t * in_p) {
  uint8_t be[LURCH_OM2_KEY_LEN];
  gcry_mpi_t mpi = (void *) 0;

  for (int i = 0; i < LURCH_OM2_KEY_LEN; i++) {
    be[i] = in_p[LURCH_OM2_KEY_LEN - 1 - i];
  }

  if (gcry_mpi_scan(&mpi, GCRYMPI_FMT_USG, be, sizeof(be), (void *) 0)) {
    return (void *) 0;
  }

  return mpi;
}

/** Writes a little endian field element. */
static int lurch_om2_mpi_to_le(gcry_mpi_t mpi, uint8_t * out_p) {
  uint8_t be[LURCH_OM2_KEY_LEN];
  size_t written = 0;

  if (gcry_mpi_print(GCRYMPI_FMT_USG, be, sizeof(be), &written, mpi)) {
    return -1;
  }

  // the most significant bytes are missing if they are zero
  memset(out_p, 0, LURCH_OM2_KEY_LEN);
  for (size_t i = 0; i < written; i++) {
    out_p[i] = be[written - 1 - i];
  }

  return 0;
}

/**
 * Both directions of the map between the curves:
 * u = (1 + y) / (1 - y)
 * y = (u - 1) / (u + 1)
 */
static int lurch_om2_map(const uint8_t * in_p, uint8_t * out_p, int to_curve) {
  int ret_val = -1;
  gcry_mpi_t p = (void *) 0;
  gcry_mpi_t v = lurch_om2_mpi_from_le(in_p);
  gcry_mpi_t one = gcry_mpi_set_ui((void *) 0, 1);
  gcry_mpi_t num = gcry_mpi_new(0);
  gcry_mpi_t den = gcry_mpi_new(0);
  gcry_mpi_t inv = gcry_mpi_new(0);
  gcry_mpi_t res = gcry_mpi_new(0);

  if (!v || gcry_mpi_scan(&p, GCRYMPI_FMT_HEX, P25519_HEX, 0, (void *) 0)) {
    goto cleanup;
  }

  // non-canonical encodings would allow multiple representations of one key
  if (gcry_mpi_cmp(v, p) >= 0) {
    goto cleanup;
  }

  if (to_curve) {
    gcry_mpi_addm(num, one, v, p);
    gcry_mpi_subm(den, one, v, p);
  } else {
    gcry_mpi_subm(num, v, one, p);
    gcry_mpi_addm(den, v, one, p);
  }

  // the denominator is zero for the low order points, which are not valid keys
  if (!gcry_mpi_invm(inv, den, p)) {
    goto cleanup;
  }

  gcry_mpi_mulm(res, num, inv, p);
  ret_val = lurch_om2_mpi_to_le(res, out_p);

cleanup:
  gcry_mpi_release(p);
  gcry_mpi_release(v);
  gcry_mpi_release(one);
  gcry_mpi_release(num);
  gcry_mpi_release(den);
  gcry_mpi_release(inv);
  gcry_mpi_release(res);
  return ret_val;
}

int lurch_om2_ed_to_curve(const uint8_t * ed_p, uint8_t * curve_p) {
  uint8_t y[LURCH_OM2_KEY_LEN];

  memcpy(y, ed_p, sizeof(y));
  y[31] &= 0x7F;

  return lurch_om2_map(y, curve_p, 1);
}

int lurch_om2_curve_to_ed(const uint8_t * curve_p, uint8_t * ed_p) {
  uint8_t u[LURCH_OM2_KEY_LEN];

  memcpy(u, curve_p, sizeof(u));
  u[31] &= 0x7F;

  return lurch_om2_map(u, ed_p, 0);
}

/** Reduces little endian bytes modulo the order of the base point, into a secure MPI. */
static gcry_mpi_t lurch_om2_scalar_from_le(const uint8_t * in_p, size_t len, gcry_mpi_t l) {
  uint8_t * be_p = gcry_malloc_secure(len);
  gcry_mpi_t raw = (void *) 0;
  gcry_mpi_t out = gcry_mpi_snew(0);

  if (!be_p) {
    gcry_mpi_release(out);
    return (void *) 0;
  }

  for (size_t i = 0; i < len; i++) {
    be_p[i] = in_p[len - 1 - i];
  }

  if (gcry_mpi_scan(&raw, GCRYMPI_FMT_USG, be_p, len, (void *) 0)) {
    gcry_mpi_release(out);
    out = (void *) 0;
  } else {
    gcry_mpi_mod(out, raw, l);
  }

  gcry_mpi_release(raw);
  lurch_om2_wipe(be_p, len);
  gcry_free(be_p);
  return out;
}

/** Calculates scalar * base point and encodes the result as defined by RFC 8032. */
static int lurch_om2_ed_mul_base(gcry_mpi_t scalar, gcry_ctx_t ec, uint8_t * out_p) {
  gcry_mpi_point_t g = gcry_mpi_ec_get_point("g", ec, 1);
  gcry_mpi_point_t q = gcry_mpi_point_new(0);
  gcry_mpi_t x = gcry_mpi_new(0);
  gcry_mpi_t y = gcry_mpi_new(0);
  int ret_val = -1;

  gcry_mpi_ec_mul(q, scalar, g, ec);

  if (!gcry_mpi_ec_get_affine(x, y, q, ec) && !lurch_om2_mpi_to_le(y, out_p)) {
    out_p[31] |= gcry_mpi_test_bit(x, 0) ? 0x80 : 0;
    ret_val = 0;
  }

  gcry_mpi_point_release(g);
  gcry_mpi_point_release(q);
  gcry_mpi_release(x);
  gcry_mpi_release(y);
  return ret_val;
}

/** SHA-512 of the concatenation of up to four inputs. */
static int lurch_om2_sha512(const uint8_t * a_p, size_t a_len, const uint8_t * b_p, size_t b_len, const uint8_t * c_p, size_t c_len, const uint8_t * d_p, size_t d_len, uint8_t * out_p) {
  gcry_md_hd_t hd = (void *) 0;

  if (gcry_md_open(&hd, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE)) {
    return -1;
  }

  gcry_md_write(hd, a_p, a_len);
  gcry_md_write(hd, b_p, b_len);
  gcry_md_write(hd, c_p, c_len);
  gcry_md_write(hd, d_p, d_len);
  memcpy(out_p, gcry_md_read(hd, GCRY_MD_SHA512), 64);
  gcry_md_close(hd);
  return 0;
}

int lurch_om2_xeddsa_sign(const uint8_t * priv_p, const uint8_t * msg_p, size_t msg_len, uint8_t * sig_p) {
  uint8_t clamped[LURCH_OM2_KEY_LEN];
  uint8_t a_enc[LURCH_OM2_KEY_LEN];
  uint8_t a_bytes[LURCH_OM2_KEY_LEN];
  uint8_t r_enc[LURCH_OM2_KEY_LEN];
  uint8_t prefix[LURCH_OM2_KEY_LEN];
  uint8_t z[64];
  uint8_t digest[64];
  gcry_ctx_t ec = (void *) 0;
  gcry_mpi_t l = (void *) 0;
  gcry_mpi_t a = (void *) 0;
  gcry_mpi_t r = (void *) 0;
  gcry_mpi_t h = (void *) 0;
  gcry_mpi_t s = gcry_mpi_snew(0);
  gcry_mpi_t prod = gcry_mpi_snew(0);
  int ret_val = -1;

  if (gcry_mpi_ec_new(&ec, (void *) 0, "Ed25519")) {
    goto cleanup;
  }
  l = gcry_mpi_ec_get_mpi("n", ec, 1);
  if (!l) {
    goto cleanup;
  }

  memcpy(clamped, priv_p, sizeof(clamped));
  clamped[0] &= 248;
  clamped[31] &= 127;
  clamped[31] |= 64;

  a = lurch_om2_scalar_from_le(clamped, sizeof(clamped), l);
  if (!a || lurch_om2_ed_mul_base(a, ec, a_enc)) {
    goto cleanup;
  }

  // The Edwards point is fixed to the one with sign 0, which is the only one known to anybody with just the public
  // Curve25519 key. If the private key gives the other one, using its negation gives the right one.
  if (a_enc[31] & 0x80) {
    gcry_mpi_subm(a, l, a, l);
    a_enc[31] &= 0x7F;
  }

  if (lurch_om2_mpi_to_le(a, a_bytes)) {
    goto cleanup;
  }

  // r = hash1(a || M || Z) mod q, with hash1 being SHA-512 prefixed by 0xFE and 31 * 0xFF
  memset(prefix, 0xFF, sizeof(prefix));
  prefix[0] = 0xFE;
  lurch_om2_random(z, sizeof(z));
  if (lurch_om2_sha512(prefix, sizeof(prefix), a_bytes, sizeof(a_bytes), msg_p, msg_len, z, sizeof(z), digest)) {
    goto cleanup;
  }

  r = lurch_om2_scalar_from_le(digest, sizeof(digest), l);
  if (!r || lurch_om2_ed_mul_base(r, ec, r_enc)) {
    goto cleanup;
  }

  // h = hash(R || A || M) mod q
  if (lurch_om2_sha512(r_enc, sizeof(r_enc), a_enc, sizeof(a_enc), msg_p, msg_len, (void *) "", 0, digest)) {
    goto cleanup;
  }
  h = lurch_om2_scalar_from_le(digest, sizeof(digest), l);
  if (!h) {
    goto cleanup;
  }

  // s = r + h * a mod q
  gcry_mpi_mulm(prod, h, a, l);
  gcry_mpi_addm(s, r, prod, l);

  memcpy(sig_p, r_enc, LURCH_OM2_KEY_LEN);
  ret_val = lurch_om2_mpi_to_le(s, sig_p + LURCH_OM2_KEY_LEN);

cleanup:
  lurch_om2_wipe(clamped, sizeof(clamped));
  lurch_om2_wipe(a_bytes, sizeof(a_bytes));
  lurch_om2_wipe(z, sizeof(z));
  lurch_om2_wipe(digest, sizeof(digest));
  gcry_mpi_release(l);
  gcry_mpi_release(a);
  gcry_mpi_release(r);
  gcry_mpi_release(h);
  gcry_mpi_release(s);
  gcry_mpi_release(prod);
  gcry_ctx_release(ec);
  return ret_val;
}

int lurch_om2_ed_verify(const uint8_t * ed_p, const uint8_t * msg_p, size_t msg_len, const uint8_t * sig_p) {
  gcry_sexp_t key = (void *) 0;
  gcry_sexp_t data = (void *) 0;
  gcry_sexp_t sig = (void *) 0;
  int ret_val = -1;

  if (gcry_sexp_build(&key, (void *) 0, "(public-key (ecc (curve \"Ed25519\") (flags eddsa) (q %b)))", LURCH_OM2_KEY_LEN, ed_p)
      || gcry_sexp_build(&data, (void *) 0, "(data (flags eddsa) (hash-algo sha512) (value %b))", (int) msg_len, msg_p)
      || gcry_sexp_build(&sig, (void *) 0, "(sig-val (eddsa (r %b) (s %b)))", LURCH_OM2_SIG_LEN / 2, sig_p, LURCH_OM2_SIG_LEN / 2, sig_p + LURCH_OM2_SIG_LEN / 2)) {
    goto cleanup;
  }

  ret_val = gcry_pk_verify(sig, data, key) ? -1 : 0;

cleanup:
  gcry_sexp_release(key);
  gcry_sexp_release(data);
  gcry_sexp_release(sig);
  return ret_val;
}
