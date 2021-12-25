#pragma once

#include <cstdio>
#include <array>


namespace Crypto {
    bool generate_random_bytes(uint8_t *buf, size_t len);

    bool generate_keypair(
        std::array<uint8_t, 32> &key_private,
        std::array<uint8_t, 32> &key_public
    );

    bool derive_dhkey(
        const std::array<uint8_t, 32> &key_private,
        const std::array<uint8_t, 32> &key_public,
        std::array<uint8_t, 32> &dhkey
    );

    bool compute_aes_128_cmac(
        const std::array<uint8_t, 16> &key,
        const uint8_t *msg,
        size_t msg_len,
        std::array<uint8_t, 16> &mac
    );

    bool decrypt_aes_ccm(
        const std::array<uint8_t, 16> &key,
        const std::array<uint8_t, 13> &nonce,
        const uint8_t *cipher_msg,
        size_t msg_len,
        uint8_t *plaintext,
        const std::array<uint8_t, 16> &tag
    );
}
