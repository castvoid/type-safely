#pragma once

#include <cstdio>
#include <array>
#include <openssl/cmac.h>
#include <openssl/rand.h>

extern "C" {
#include "curve25519_donna.h"
}


static bool generate_random_bytes(uint8_t *buf, size_t len) {
    if (len > INT_MAX) return false;
    return RAND_bytes(buf, static_cast<int>(len)) == 1;
}


namespace Crypto {
    template<std::size_t len_private, std::size_t len_public> bool generate_keypair(
        std::array<uint8_t, len_private> &key_private,
        std::array<uint8_t, len_public> &key_public
    ) {
        static_assert(len_private == 32);
        static_assert(len_public == 32);

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

    template<std::size_t len_private, std::size_t len_public, std::size_t len_dhkey> bool derive_dhkey(
        const std::array<uint8_t, len_private> &key_private,
        const std::array<uint8_t, len_public> &key_public,
        std::array<uint8_t, len_dhkey> &dhkey
    ) {
        static_assert(len_private == 32);
        static_assert(len_public == 32);
        static_assert(len_dhkey == 32);

        curve25519_donna(dhkey.data(), key_private.data(), key_public.data());

        return true;
    }

    bool compute_aes_128_cmac(const std::array<uint8_t, 16> &key,
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

};
