#include "crypto.h"
#include "assert.h"

#include <openssl/cmac.h>
#include <openssl/rand.h>
extern "C" {
#include "curve25519_donna.h"
}


bool Crypto::generate_random_bytes(uint8_t *buf, size_t len) {
    if (len > INT_MAX) return false;
    return RAND_bytes(buf, static_cast<int>(len)) == 1;
}


bool Crypto::generate_keypair(
    std::array<uint8_t, 32> &key_private,
    std::array<uint8_t, 32> &key_public
) {
    if (!generate_random_bytes(key_private.data(), key_private.size())) return false;

    // transform to a valid Curve25519 private key, using D. J. Bernstein's method
    key_private[0] &= 248;
    key_private[31] &= 127;
    key_private[31] |= 64;

    // Compute public key
    const uint8_t basepoint[32] = {9};
    curve25519_donna(key_public.data(), key_private.data(), basepoint);

    return true;
}


bool Crypto::derive_dhkey(
    const std::array<uint8_t, 32> &key_private,
    const std::array<uint8_t, 32> &key_public,
    std::array<uint8_t, 32> &dhkey
) {
    curve25519_donna(dhkey.data(), key_private.data(), key_public.data());

    return true;
}


bool Crypto::compute_aes_128_cmac(const std::array<uint8_t, 16> &key,
                          const uint8_t *msg,
                          size_t msg_len,
                          std::array<uint8_t, 16> &mac) {
    bool succeeded = false;
    size_t mac_len;

    CMAC_CTX *ctx = CMAC_CTX_new();
    if (ctx == nullptr) return false;

    if (CMAC_Init(ctx, key.data(), key.size(), EVP_aes_128_cbc(), nullptr) != 1) goto fail;
    if (CMAC_Update(ctx, msg, msg_len) != 1) goto fail;
    if (CMAC_Final(ctx, mac.data(), &mac_len) != 1) goto fail;

    assert(mac_len == mac.size());

    succeeded = true;
    fail:
    CMAC_CTX_free(ctx);
    return succeeded;
}

bool Crypto::decrypt_aes_ccm(const std::array<uint8_t, 16> &key, const std::array<uint8_t, 13> &nonce, const uint8_t *cipher_msg, size_t msg_len, uint8_t *plaintext, const std::array<uint8_t, 16> &tag) {
    if (msg_len > INT_MAX) return false;
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int ret = -1;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;

    // Init ctx
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), nullptr, nullptr, nullptr) != 1) goto fail;

    // Set IV/nonce length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, nonce.size(), nullptr) != 1) goto fail;

    // Set the expected tag value
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag.size(), const_cast<uint8_t*>(tag.data())) != 1) goto fail;

    // Set the key and IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) goto fail;

    // Set the ciphertext length
    if (EVP_DecryptUpdate(ctx, nullptr, &len, nullptr, static_cast<int>(msg_len)) != 1) goto fail;

    // Calculate plaintext
    ret = EVP_DecryptUpdate(ctx, plaintext, &len, cipher_msg, static_cast<int>(msg_len));
    assert(len > 0 && static_cast<unsigned int>(len) == msg_len);

    fail:
    EVP_CIPHER_CTX_free(ctx);
    return ret > 0;
}