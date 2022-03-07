#include <stdio.h>

#include "blake2/blake2s-ref.c"
#include "base64/base64.c"


#include "chacha20poly1305/poly1305-donna.c"
#include "chacha20poly1305/chacha_merged.c"
#include "chacha20poly1305/chacha20poly1305.c"

#define COOKIE_KEY_LABEL_LEN 8
#define NOISE_SYMMETRIC_KEY_LEN 32
#define NOISE_PUBLIC_KEY_LEN 32 // unsure
#define COOKIE_LEN 16 // This is also the length of the mac fields

#define BASE64_PUBLIC_KEY_LEN 44 // PUBLIC_KEY in Base64

static const uint8_t wg_mac1_key_label[COOKIE_KEY_LABEL_LEN] = "mac1----";
static const uint8_t wg_cookie_key_label[COOKIE_KEY_LABEL_LEN] = "cookie--";

static void wg_precompute_key(uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
			   const uint8_t pubkey[NOISE_PUBLIC_KEY_LEN],
			   const uint8_t label[COOKIE_KEY_LABEL_LEN])
{

	struct blake2s_state__ blake;

	blake2s_init(&blake, NOISE_SYMMETRIC_KEY_LEN);
	blake2s_update(&blake, label, COOKIE_KEY_LABEL_LEN);
	blake2s_update(&blake, pubkey, NOISE_PUBLIC_KEY_LEN);
	blake2s_final(&blake, key, NOISE_SYMMETRIC_KEY_LEN);
}

void wg_mac1(uint8_t mac1[COOKIE_LEN], uint8_t pubkey[NOISE_PUBLIC_KEY_LEN], const void *msg, int len)
{
    /*
	precompute_key(peer->latest_cookie.message_mac1_key,
		       peer->handshake.remote_static, mac1_key_label);
    */
    uint8_t pre_key[NOISE_SYMMETRIC_KEY_LEN];
    wg_precompute_key(pre_key, pubkey, wg_mac1_key_label);

    /*
    compute_mac1(macs->mac1, message, len,
                peer->latest_cookie.message_mac1_key);
    -----------------------------------------------------------------------
    static void compute_mac1(u8 mac1[COOKIE_LEN], const void *message, size_t len,
                            const u8 key[NOISE_SYMMETRIC_KEY_LEN])
    {
        len = len - sizeof(struct message_macs) +
            offsetof(struct message_macs, mac1);
        blake2s(mac1, message, key, COOKIE_LEN, len, NOISE_SYMMETRIC_KEY_LEN);
    }
    */

    blake2s(mac1, COOKIE_LEN, msg, len, pre_key, NOISE_SYMMETRIC_KEY_LEN);
}

void wg_mac2(uint8_t mac2[COOKIE_LEN], const uint8_t cookie[COOKIE_LEN], const void *msg, int len)
{
    /*
    compute_mac2(macs->mac2, message, len,
			     peer->latest_cookie.cookie);
    -----------------------------------------------------------------------
    static void compute_mac2(u8 mac2[COOKIE_LEN], const void *message, size_t len,
                const u8 cookie[COOKIE_LEN])
    {
        len = len - sizeof(struct message_macs) +
            offsetof(struct message_macs, mac2);
        blake2s(mac2, message, cookie, COOKIE_LEN, len, COOKIE_LEN);
    }
    */

    blake2s(mac2, COOKIE_LEN, msg, len, cookie, COOKIE_LEN);
}


int wg_decode_pubkey(uint8_t out[NOISE_PUBLIC_KEY_LEN], const char in_base64[BASE64_PUBLIC_KEY_LEN])
{
    return b64_decode(in_base64, out, NOISE_PUBLIC_KEY_LEN);
}


int wg_encode_pubkey(char out_base64[BASE64_PUBLIC_KEY_LEN], const uint8_t in[NOISE_PUBLIC_KEY_LEN])
{
    return b64_encode(in, out_base64, BASE64_PUBLIC_KEY_LEN);
}


int wg_cookie_decrypt(uint8_t cookie[16], uint8_t pubkey[32], uint8_t nonce[24], uint8_t cookie_enc[32], uint8_t mac1[16])
{
    
    // key is the cookie_decryption_key
    uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
    wg_precompute_key(key, pubkey, wg_cookie_key_label);


	chacha20poly1305_ctx ctx;
    
    xchacha20poly1305_init(&ctx, key, nonce);

    // mac1 is authentication tag
    chacha20poly1305_auth(&ctx, mac1, 16);

    // requires size of ciphertext
    chacha20poly1305_decrypt(&ctx, cookie_enc, cookie, 16);


    // authenticate data (not working)
    /*
    uint8_t tag[16];
    chacha20poly1305_finish(&ctx, tag);
    int res = memcmp(tag, cookie_enc+16, 16);
    */

    return 1;
}