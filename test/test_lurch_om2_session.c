#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <string.h>

#include <gcrypt.h>
#include <glib.h>

#include "../src/lurch_om2_crypto.h"
#include "../src/lurch_om2_session.h"

typedef struct {
  uint8_t * data_p;
  size_t len;
} blob;

typedef struct {
  lurch_om2_keypair ik_a;
  lurch_om2_keypair ik_b;
  lurch_om2_keypair spk;
  lurch_om2_keypair pk;
  lurch_om2_session * a_p;
  lurch_om2_session * b_p;
} peers;

static void hex_to_bytes(const char * hex, uint8_t * out_p) {
  size_t len = strlen(hex) / 2;

  for (size_t i = 0; i < len; i++) {
    unsigned int value = 0;
    assert_int_equal(sscanf(hex + 2 * i, "%2x", &value), 1);
    out_p[i] = (uint8_t) value;
  }
}

static void assert_hex_equal(const uint8_t * actual_p, const char * hex) {
  uint8_t expected[128];

  hex_to_bytes(hex, expected);
  assert_memory_equal(actual_p, expected, strlen(hex) / 2);
}

static blob encrypt_str(lurch_om2_session * session_p, const char * msg, int * is_kex_p) {
  blob out = {0};
  int is_kex = 0;

  assert_int_equal(lurch_om2_session_encrypt(session_p, (const uint8_t *) msg, strlen(msg), &out.data_p, &out.len, &is_kex), 0);
  if (is_kex_p) {
    *is_kex_p = is_kex;
  }

  return out;
}

static void assert_decrypts(lurch_om2_session * session_p, const uint8_t * msg_p, size_t msg_len, const char * expected) {
  uint8_t * plain_p = (void *) 0;
  size_t plain_len = 0;
  int heartbeat = 0;

  assert_int_equal(lurch_om2_session_decrypt(session_p, msg_p, msg_len, &plain_p, &plain_len, &heartbeat), 0);
  assert_int_equal(plain_len, strlen(expected));
  assert_memory_equal(plain_p, expected, plain_len);
  g_free(plain_p);
}

static lurch_om2_session * session_clone(const lurch_om2_session * session_p) {
  uint8_t * state_p = (void *) 0;
  size_t state_len = 0;
  lurch_om2_session * clone_p = (void *) 0;

  assert_int_equal(lurch_om2_session_serialize(session_p, &state_p, &state_len), 0);
  assert_int_equal(lurch_om2_session_deserialize(state_p, state_len, &clone_p), 0);
  g_free(state_p);

  return clone_p;
}

static void bundle_create(const peers * p_p, lurch_om2_bundle * bundle_p) {
  memset(bundle_p, 0, sizeof(*bundle_p));
  assert_int_equal(lurch_om2_curve_to_ed(p_p->ik_b.pub, bundle_p->ik_ed), 0);
  bundle_p->spk_id = 7;
  memcpy(bundle_p->spk, p_p->spk.pub, LURCH_OM2_KEY_LEN);
  assert_int_equal(lurch_om2_xeddsa_sign(p_p->ik_b.priv, p_p->spk.pub, LURCH_OM2_KEY_LEN, bundle_p->spk_sig), 0);
  bundle_p->pk_id = 9;
  memcpy(bundle_p->pk, p_p->pk.pub, LURCH_OM2_KEY_LEN);
}

/** Sets up two peers with an established session, with B having received the first message and A a response. */
static void peers_create(peers * p_p) {
  lurch_om2_bundle bundle;
  lurch_om2_key_exchange kex;
  blob first;
  blob reply;

  memset(p_p, 0, sizeof(*p_p));
  assert_int_equal(lurch_om2_x25519_generate(&p_p->ik_a), 0);
  assert_int_equal(lurch_om2_x25519_generate(&p_p->ik_b), 0);
  assert_int_equal(lurch_om2_x25519_generate(&p_p->spk), 0);
  assert_int_equal(lurch_om2_x25519_generate(&p_p->pk), 0);

  bundle_create(p_p, &bundle);
  assert_int_equal(lurch_om2_session_create_active(&p_p->ik_a, &bundle, &p_p->a_p), 0);

  first = encrypt_str(p_p->a_p, "first", (void *) 0);
  assert_int_equal(lurch_om2_key_exchange_parse(first.data_p, first.len, &kex), 0);
  assert_int_equal(lurch_om2_session_create_passive(&p_p->ik_b, &p_p->spk, &p_p->pk, &kex, &p_p->b_p), 0);
  assert_decrypts(p_p->b_p, kex.msg_p, kex.msg_len, "first");

  reply = encrypt_str(p_p->b_p, "reply", (void *) 0);
  assert_decrypts(p_p->a_p, reply.data_p, reply.len, "reply");

  g_free(first.data_p);
  g_free(reply.data_p);
}

static void peers_destroy(peers * p_p) {
  lurch_om2_session_destroy(p_p->a_p);
  lurch_om2_session_destroy(p_p->b_p);
}

/** RFC 4231, test case 2 */
static void test_hmac_vector(void ** state) {
  (void) state;
  uint8_t out[32];

  assert_int_equal(lurch_om2_hmac((const uint8_t *) "Jefe", 4, (const uint8_t *) "what do ya want for nothing?", 28, out), 0);
  assert_hex_equal(out, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

/** RFC 5869, test case 3, which has no salt and no info */
static void test_hkdf_vector(void ** state) {
  (void) state;
  uint8_t ikm[22];
  uint8_t out[42];

  memset(ikm, 0x0b, sizeof(ikm));
  assert_int_equal(lurch_om2_hkdf((void *) 0, 0, ikm, sizeof(ikm), "", out, sizeof(out)), 0);
  assert_hex_equal(out, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
}

/** RFC 7748, section 6.1 */
static void test_x25519_vector(void ** state) {
  (void) state;
  static const uint8_t base[LURCH_OM2_KEY_LEN] = {9};
  uint8_t priv_a[LURCH_OM2_KEY_LEN];
  uint8_t priv_b[LURCH_OM2_KEY_LEN];
  uint8_t pub_b[LURCH_OM2_KEY_LEN];
  uint8_t out[LURCH_OM2_KEY_LEN];

  hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", priv_a);
  hex_to_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", priv_b);

  assert_int_equal(lurch_om2_x25519(priv_a, base, out), 0);
  assert_hex_equal(out, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  assert_int_equal(lurch_om2_x25519(priv_b, base, pub_b), 0);
  assert_int_equal(lurch_om2_x25519(priv_a, pub_b, out), 0);
  assert_hex_equal(out, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
}

static void test_x25519_rejects_low_order(void ** state) {
  (void) state;
  static const uint8_t zero[LURCH_OM2_KEY_LEN] = {0};
  uint8_t priv[LURCH_OM2_KEY_LEN] = {1, 2, 3};
  uint8_t out[LURCH_OM2_KEY_LEN];

  assert_int_not_equal(lurch_om2_x25519(priv, zero, out), 0);
}

/** RFC 8032, test 1 */
static void test_ed_verify_vector(void ** state) {
  (void) state;
  uint8_t pub[LURCH_OM2_KEY_LEN];
  uint8_t sig[LURCH_OM2_SIG_LEN];

  hex_to_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", pub);
  hex_to_bytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", sig);

  assert_int_equal(lurch_om2_ed_verify(pub, (const uint8_t *) "", 0, sig), 0);
  sig[0] ^= 1;
  assert_int_not_equal(lurch_om2_ed_verify(pub, (const uint8_t *) "", 0, sig), 0);
}

/** RFC 7748, section 4.1: the base points of the curves are mapped to each other. */
static void test_curve_map_vector(void ** state) {
  (void) state;
  static const uint8_t base[LURCH_OM2_KEY_LEN] = {9};
  uint8_t ed[LURCH_OM2_KEY_LEN];
  uint8_t curve[LURCH_OM2_KEY_LEN];

  assert_int_equal(lurch_om2_curve_to_ed(base, ed), 0);
  assert_hex_equal(ed, "5866666666666666666666666666666666666666666666666666666666666666");
  assert_int_equal(lurch_om2_ed_to_curve(ed, curve), 0);
  assert_memory_equal(curve, base, LURCH_OM2_KEY_LEN);
}

static void test_curve_map_rejects_invalid(void ** state) {
  (void) state;
  uint8_t one[LURCH_OM2_KEY_LEN] = {1};
  uint8_t non_canonical[LURCH_OM2_KEY_LEN];
  uint8_t out[LURCH_OM2_KEY_LEN];

  memset(non_canonical, 0xFF, sizeof(non_canonical));
  non_canonical[31] = 0x7F;

  assert_int_not_equal(lurch_om2_ed_to_curve(one, out), 0);
  assert_int_not_equal(lurch_om2_ed_to_curve(non_canonical, out), 0);
}

/**
 * The sign of the Edwards key is different for about half of all private keys, so a low number of tries would pass
 * with broken handling of it. That is what happens with libsignal's own function for signing.
 */
static void test_xeddsa_is_valid_for_all_keys(void ** state) {
  (void) state;
  static const char * const msg = "message";

  for (int i = 0; i < 128; i++) {
    lurch_om2_keypair kp;
    uint8_t ed[LURCH_OM2_KEY_LEN];
    uint8_t sig[LURCH_OM2_SIG_LEN];

    assert_int_equal(lurch_om2_x25519_generate(&kp), 0);
    assert_int_equal(lurch_om2_curve_to_ed(kp.pub, ed), 0);
    assert_int_equal(lurch_om2_xeddsa_sign(kp.priv, (const uint8_t *) msg, strlen(msg), sig), 0);
    assert_int_equal(lurch_om2_ed_verify(ed, (const uint8_t *) msg, strlen(msg), sig), 0);

    sig[10] ^= 1;
    assert_int_not_equal(lurch_om2_ed_verify(ed, (const uint8_t *) msg, strlen(msg), sig), 0);
  }
}

static void test_aes_vector_and_padding(void ** state) {
  (void) state;
  uint8_t key[LURCH_OM2_KEY_LEN];
  uint8_t iv[LURCH_OM2_IV_LEN];
  uint8_t plain[16];
  uint8_t * ct_p = (void *) 0;
  uint8_t * pt_p = (void *) 0;
  size_t ct_len = 0;
  size_t pt_len = 0;

  // NIST SP 800-38A F.2.5, with a whole block of padding following
  hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key);
  hex_to_bytes("000102030405060708090a0b0c0d0e0f", iv);
  hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", plain);

  assert_int_equal(lurch_om2_aes_encrypt(key, iv, plain, sizeof(plain), &ct_p, &ct_len), 0);
  assert_int_equal(ct_len, 32);
  assert_hex_equal(ct_p, "f58c4c04d6e5f1ba779eabfb5f7bfbd6");

  assert_int_equal(lurch_om2_aes_decrypt(key, iv, ct_p, ct_len, &pt_p, &pt_len), 0);
  assert_int_equal(pt_len, sizeof(plain));
  assert_memory_equal(pt_p, plain, sizeof(plain));
  g_free(pt_p);

  assert_int_not_equal(lurch_om2_aes_decrypt(key, iv, ct_p, ct_len - 1, &pt_p, &pt_len), 0);
  g_free(ct_p);
}

static void test_active_rejects_forged_signature(void ** state) {
  (void) state;
  peers p;
  lurch_om2_bundle bundle;
  lurch_om2_session * session_p = (void *) 0;

  peers_create(&p);
  bundle_create(&p, &bundle);
  bundle.spk_sig[3] ^= 1;

  assert_int_equal(lurch_om2_session_create_active(&p.ik_a, &bundle, &session_p), LURCH_OM2_ERR_AUTH);
  assert_null(session_p);

  peers_destroy(&p);
}

/** A key exchange is sent until something was received, and stops afterwards. */
static void test_key_exchange_is_repeated_until_response(void ** state) {
  (void) state;
  peers p;
  lurch_om2_bundle bundle;
  lurch_om2_session * a_p = (void *) 0;
  lurch_om2_session * b_p = (void *) 0;
  lurch_om2_key_exchange kex;
  int is_kex = 0;

  peers_create(&p);
  bundle_create(&p, &bundle);
  assert_int_equal(lurch_om2_session_create_active(&p.ik_a, &bundle, &a_p), 0);

  blob first = encrypt_str(a_p, "first", &is_kex);
  assert_int_equal(is_kex, 1);
  assert_int_equal(lurch_om2_key_exchange_parse(first.data_p, first.len, &kex), 0);
  assert_int_equal(kex.pk_id, 9);
  assert_int_equal(kex.spk_id, 7);
  assert_int_equal(lurch_om2_session_create_passive(&p.ik_b, &p.spk, &p.pk, &kex, &b_p), 0);

  // there is no chain for sending yet
  uint8_t * out_p = (void *) 0;
  size_t out_len = 0;
  assert_int_not_equal(lurch_om2_session_encrypt(b_p, (const uint8_t *) "x", 1, &out_p, &out_len, &is_kex), 0);

  assert_decrypts(b_p, kex.msg_p, kex.msg_len, "first");
  assert_true(lurch_om2_session_has_remote_ek(b_p, kex.ek));

  blob second = encrypt_str(a_p, "second", &is_kex);
  assert_int_equal(is_kex, 1);
  assert_int_equal(lurch_om2_key_exchange_parse(second.data_p, second.len, &kex), 0);
  assert_true(lurch_om2_session_has_remote_ek(b_p, kex.ek));
  assert_decrypts(b_p, kex.msg_p, kex.msg_len, "second");

  blob reply = encrypt_str(b_p, "reply", &is_kex);
  assert_int_equal(is_kex, 0);
  assert_decrypts(a_p, reply.data_p, reply.len, "reply");

  blob third = encrypt_str(a_p, "third", &is_kex);
  assert_int_equal(is_kex, 0);
  assert_decrypts(b_p, third.data_p, third.len, "third");

  g_free(first.data_p);
  g_free(second.data_p);
  g_free(reply.data_p);
  g_free(third.data_p);
  lurch_om2_session_destroy(a_p);
  lurch_om2_session_destroy(b_p);
  peers_destroy(&p);
}

static void test_serialized_session_continues(void ** state) {
  (void) state;
  peers p;

  peers_create(&p);

  lurch_om2_session * a_p = session_clone(p.a_p);
  lurch_om2_session * b_p = session_clone(p.b_p);

  blob msg = encrypt_str(a_p, "reloaded", (void *) 0);
  assert_decrypts(b_p, msg.data_p, msg.len, "reloaded");
  blob reply = encrypt_str(b_p, "reloaded reply", (void *) 0);
  assert_decrypts(a_p, reply.data_p, reply.len, "reloaded reply");

  g_free(msg.data_p);
  g_free(reply.data_p);
  lurch_om2_session_destroy(a_p);
  lurch_om2_session_destroy(b_p);
  peers_destroy(&p);
}

static void test_deserialize_rejects_garbage(void ** state) {
  (void) state;
  static const uint8_t garbage[8] = {1, 2, 3};
  lurch_om2_session * session_p = (void *) 0;

  assert_int_not_equal(lurch_om2_session_deserialize(garbage, sizeof(garbage), &session_p), 0);
  assert_null(session_p);
}

/** Includes a message that was sent in a chain before the current one. */
static void test_out_of_order(void ** state) {
  (void) state;
  peers p;
  blob msgs[4];

  peers_create(&p);

  for (int i = 0; i < 4; i++) {
    char text[8];
    g_snprintf(text, sizeof(text), "m%d", i);
    msgs[i] = encrypt_str(p.a_p, text, (void *) 0);
  }

  assert_decrypts(p.b_p, msgs[3].data_p, msgs[3].len, "m3");
  assert_decrypts(p.b_p, msgs[1].data_p, msgs[1].len, "m1");

  blob back = encrypt_str(p.b_p, "back", (void *) 0);
  assert_decrypts(p.a_p, back.data_p, back.len, "back");
  blob next = encrypt_str(p.a_p, "next", (void *) 0);
  assert_decrypts(p.b_p, next.data_p, next.len, "next");

  assert_decrypts(p.b_p, msgs[0].data_p, msgs[0].len, "m0");
  assert_decrypts(p.b_p, msgs[2].data_p, msgs[2].len, "m2");

  for (int i = 0; i < 4; i++) {
    g_free(msgs[i].data_p);
  }
  g_free(back.data_p);
  g_free(next.data_p);
  peers_destroy(&p);
}

/** Received twice must not be an error for the user, and must not change the session by causing a ratchet step. */
static void test_duplicates(void ** state) {
  (void) state;
  peers p;
  uint8_t * out_p = (void *) 0;
  size_t out_len = 0;
  int heartbeat = 0;

  peers_create(&p);

  blob old_chain = encrypt_str(p.a_p, "old", (void *) 0);
  assert_decrypts(p.b_p, old_chain.data_p, old_chain.len, "old");

  blob back = encrypt_str(p.b_p, "back", (void *) 0);
  assert_decrypts(p.a_p, back.data_p, back.len, "back");

  blob current = encrypt_str(p.a_p, "current", (void *) 0);
  assert_decrypts(p.b_p, current.data_p, current.len, "current");

  assert_int_equal(lurch_om2_session_decrypt(p.b_p, current.data_p, current.len, &out_p, &out_len, &heartbeat), LURCH_OM2_ERR_DUPLICATE);
  assert_int_equal(lurch_om2_session_decrypt(p.b_p, old_chain.data_p, old_chain.len, &out_p, &out_len, &heartbeat), LURCH_OM2_ERR_DUPLICATE);

  blob after = encrypt_str(p.a_p, "after", (void *) 0);
  assert_decrypts(p.b_p, after.data_p, after.len, "after");

  g_free(old_chain.data_p);
  g_free(back.data_p);
  g_free(current.data_p);
  g_free(after.data_p);
  peers_destroy(&p);
}

/** No change to any byte of a message can result in it being accepted, and the stored state still is fine. */
static void test_tampering_is_detected(void ** state) {
  (void) state;
  peers p;
  uint8_t * saved_p = (void *) 0;
  size_t saved_len = 0;

  peers_create(&p);
  assert_int_equal(lurch_om2_session_serialize(p.b_p, &saved_p, &saved_len), 0);

  blob msg = encrypt_str(p.a_p, "tamper", (void *) 0);

  for (size_t i = 0; i < msg.len; i++) {
    for (int bit = 0; bit < 8; bit++) {
      lurch_om2_session * copy_p = (void *) 0;
      uint8_t * out_p = (void *) 0;
      size_t out_len = 0;
      int heartbeat = 0;

      assert_int_equal(lurch_om2_session_deserialize(saved_p, saved_len, &copy_p), 0);
      msg.data_p[i] ^= (uint8_t) (1 << bit);
      assert_int_not_equal(lurch_om2_session_decrypt(copy_p, msg.data_p, msg.len, &out_p, &out_len, &heartbeat), 0);
      msg.data_p[i] ^= (uint8_t) (1 << bit);
      lurch_om2_session_destroy(copy_p);
    }
  }

  lurch_om2_session * restored_p = (void *) 0;
  assert_int_equal(lurch_om2_session_deserialize(saved_p, saved_len, &restored_p), 0);
  assert_decrypts(restored_p, msg.data_p, msg.len, "tamper");

  lurch_om2_session_destroy(restored_p);
  g_free(msg.data_p);
  g_free(saved_p);
  peers_destroy(&p);
}

static void test_truncated_input_is_rejected(void ** state) {
  (void) state;
  peers p;
  uint8_t * saved_p = (void *) 0;
  size_t saved_len = 0;

  peers_create(&p);
  assert_int_equal(lurch_om2_session_serialize(p.b_p, &saved_p, &saved_len), 0);

  blob msg = encrypt_str(p.a_p, "truncate", (void *) 0);

  for (size_t len = 0; len < msg.len; len++) {
    lurch_om2_session * copy_p = (void *) 0;
    lurch_om2_key_exchange kex;
    uint8_t * out_p = (void *) 0;
    size_t out_len = 0;
    int heartbeat = 0;

    assert_int_equal(lurch_om2_session_deserialize(saved_p, saved_len, &copy_p), 0);
    assert_int_not_equal(lurch_om2_session_decrypt(copy_p, msg.data_p, len, &out_p, &out_len, &heartbeat), 0);
    assert_int_not_equal(lurch_om2_key_exchange_parse(msg.data_p, len, &kex), 0);
    lurch_om2_session_destroy(copy_p);
  }

  g_free(msg.data_p);
  g_free(saved_p);
  peers_destroy(&p);
}

static void test_skip_limit(void ** state) {
  (void) state;
  peers p;
  uint8_t * out_p = (void *) 0;
  size_t out_len = 0;
  int heartbeat = 0;

  peers_create(&p);

  // there has to be a chain for this, which requires it to be a message following at least one other
  blob start = encrypt_str(p.a_p, "start", (void *) 0);
  assert_decrypts(p.b_p, start.data_p, start.len, "start");
  g_free(start.data_p);

  for (int i = 0; i < LURCH_OM2_MAX_SKIP; i++) {
    g_free(encrypt_str(p.a_p, "skipped", (void *) 0).data_p);
  }

  blob exact = encrypt_str(p.a_p, "exact", (void *) 0);
  assert_decrypts(p.b_p, exact.data_p, exact.len, "exact");
  g_free(exact.data_p);

  for (int i = 0; i < LURCH_OM2_MAX_SKIP + 1; i++) {
    g_free(encrypt_str(p.a_p, "skipped", (void *) 0).data_p);
  }

  blob too_many = encrypt_str(p.a_p, "too many", (void *) 0);
  assert_int_equal(lurch_om2_session_decrypt(p.b_p, too_many.data_p, too_many.len, &out_p, &out_len, &heartbeat), LURCH_OM2_ERR_TOO_MANY_SKIP);
  g_free(too_many.data_p);

  peers_destroy(&p);
}

static void test_heartbeat_once_at_counter(void ** state) {
  (void) state;
  peers p;
  int fired_at = -1;
  int fired = 0;

  peers_create(&p);

  // the response to the first message started a new chain on the side of A, so this one begins at 0
  for (int i = 0; i < 60; i++) {
    blob msg = encrypt_str(p.a_p, "m", (void *) 0);
    uint8_t * out_p = (void *) 0;
    size_t out_len = 0;
    int heartbeat = 0;

    assert_int_equal(lurch_om2_session_decrypt(p.b_p, msg.data_p, msg.len, &out_p, &out_len, &heartbeat), 0);
    if (heartbeat) {
      fired++;
      if (fired_at < 0) {
        fired_at = i;
      }
    }
    g_free(out_p);
    g_free(msg.data_p);
  }

  assert_int_equal(fired_at, LURCH_OM2_HEARTBEAT_COUNTER);
  assert_int_equal(fired, 1);

  peers_destroy(&p);
}

static void test_payload(void ** state) {
  (void) state;
  static const char * const msg = "<envelope/>";
  uint8_t key_and_tag[LURCH_OM2_KEY_AND_TAG_LEN];
  uint8_t * ct_p = (void *) 0;
  uint8_t * pt_p = (void *) 0;
  size_t ct_len = 0;
  size_t pt_len = 0;

  assert_int_equal(lurch_om2_payload_encrypt((const uint8_t *) msg, strlen(msg), key_and_tag, &ct_p, &ct_len), 0);
  assert_int_equal(lurch_om2_payload_decrypt(key_and_tag, ct_p, ct_len, &pt_p, &pt_len), 0);
  assert_int_equal(pt_len, strlen(msg));
  assert_memory_equal(pt_p, msg, pt_len);
  g_free(pt_p);

  ct_p[0] ^= 1;
  assert_int_equal(lurch_om2_payload_decrypt(key_and_tag, ct_p, ct_len, &pt_p, &pt_len), LURCH_OM2_ERR_AUTH);
  ct_p[0] ^= 1;

  key_and_tag[LURCH_OM2_KEY_LEN] ^= 1;
  assert_int_equal(lurch_om2_payload_decrypt(key_and_tag, ct_p, ct_len, &pt_p, &pt_len), LURCH_OM2_ERR_AUTH);

  g_free(ct_p);
}

int main(void) {
  gcry_check_version((void *) 0);
  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
  gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
  gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_hmac_vector),
    cmocka_unit_test(test_hkdf_vector),
    cmocka_unit_test(test_x25519_vector),
    cmocka_unit_test(test_x25519_rejects_low_order),
    cmocka_unit_test(test_ed_verify_vector),
    cmocka_unit_test(test_curve_map_vector),
    cmocka_unit_test(test_curve_map_rejects_invalid),
    cmocka_unit_test(test_xeddsa_is_valid_for_all_keys),
    cmocka_unit_test(test_aes_vector_and_padding),
    cmocka_unit_test(test_active_rejects_forged_signature),
    cmocka_unit_test(test_key_exchange_is_repeated_until_response),
    cmocka_unit_test(test_serialized_session_continues),
    cmocka_unit_test(test_deserialize_rejects_garbage),
    cmocka_unit_test(test_out_of_order),
    cmocka_unit_test(test_duplicates),
    cmocka_unit_test(test_tampering_is_detected),
    cmocka_unit_test(test_truncated_input_is_rejected),
    cmocka_unit_test(test_skip_limit),
    cmocka_unit_test(test_heartbeat_once_at_counter),
    cmocka_unit_test(test_payload),
  };

  return cmocka_run_group_tests_name("lurch_om2_session", tests, (void *) 0, (void *) 0);
}
