#include "Platform.hpp"
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/f4/rng.h>
#include <libopencm3/stm32/crypto.h>
#include <assert.h>
#include <debug.h>
#include <cstring>

extern "C" {
#include <cifra/aes.h>
#include <cifra/modes.h>
#include <curve25519_donna/curve25519_donna.h>
}

#define CRYP_CR_ALGOMODE_MASK   ((1 << 19) | CRYP_CR_ALGOMODE)

// TODO: move to utility class!
static inline uint64_t intToBigEndian(uint64_t input) {
#if defined(__ARMEB__)
    return input;
#elif defined(__ARMEL__)
    return __builtin_bswap64(input);
#else
#warning Endianness conversion will fail
assert(false); // TODO
return 0;
#endif
}


void Platform::Crypto::Setup() {
    rcc_periph_clock_enable(RCC_RNG);
    rng_enable();

    rcc_periph_clock_enable(RCC_CRYP);
}

bool Platform::Crypto::GetRandomBytes(uint8_t *buf, size_t len) {
    // We get 32 bits from the rng, but we need n bytes
    // So we shift the rng value 4 times before getting a new one
    // TODO: check this is actually faster - hardware RNG might actually be faster than doing this bit shifting stuff

    auto randint_raw = rng_get_random_blocking();
    constexpr size_t bytes_per_randint = sizeof(randint_raw);
    static_assert(bytes_per_randint <= UINT_FAST8_MAX);

    uint_fast8_t bytes_from_randint = 0;
    for (size_t i = 0; i < len; i++) {
        buf[i] = static_cast<uint8_t>(randint_raw & 0xFF);
        bytes_from_randint++;

        if (bytes_from_randint < bytes_per_randint){
            randint_raw >>= 8;
        } else {
            randint_raw = rng_get_random_blocking();
            bytes_from_randint = 0;
        }
    }

    return true;
}

bool Platform::Crypto::ECC::GenerateKeyPair(std::array<uint8_t, 32> &key_private, std::array<uint8_t, 32> &key_public) {
    // Generate random bytes into key_private
    if (!GetRandomBytes(key_private.data(), key_private.size())) return false;

    // transform to a valid Curve25519 private key, using D. J. Bernstein's method
    key_private[0] &= 248;
    key_private[31] &= 127;
    key_private[31] |= 64;

    // Compute public key
    const uint8_t basepoint[32] = {9};
    curve25519_donna(key_public.data(), key_private.data(), basepoint);

    return true;
}

bool Platform::Crypto::ECC::DeriveDHKey(const std::array<uint8_t, 32> &key_private, const std::array<uint8_t, 32> &key_public, std::array<uint8_t, 32> &dhkey) {
    curve25519_donna(dhkey.data(), key_private.data(), key_public.data());

    return true;
}

static const size_t AES128_KEY_SIZE = 16;
static const size_t AES128CMAC_MAC_SIZE = 16;
bool Platform::Crypto::AES128CMAC(const std::array<uint8_t, AES128_KEY_SIZE> &key, const uint8_t *msg, size_t msg_len, std::array<uint8_t, AES128CMAC_MAC_SIZE> &mac) {
    // Ensure our key is of the correct length
    static_assert(AES128_KEY_SIZE == 16 || AES128_KEY_SIZE == 24 || AES128_KEY_SIZE == 32);
    cf_aes_context aes;
    cf_aes_init(&aes, key.data(), key.size());

    // Ensure our mac output array is of the correct size
    static_assert(CF_MAXBLOCK == AES128CMAC_MAC_SIZE);

    cf_cmac cmac;
    cf_cmac_init(&cmac, &cf_aes, &aes);
    cf_cmac_sign(&cmac, msg, msg_len, mac.data());

    return true;
}

// Modified from http://libopencm3.org/docs/latest/stm32f2/html/crypto__common__f24_8c_source.html
// Part of the libopencm3 project. GNU Licenced.
static inline void crypto_process_bytes(const uint8_t *inp, size_t in_len, uint8_t *outp, size_t out_len, bool out_wrap) {
    constexpr auto blocksize = 16;
    // Ensure we write full, blocksize-byte blocks
    size_t to_write = ((in_len + blocksize - 1) / blocksize) * blocksize;

    size_t read = 0, written = 0, outp_offset = 0;

    while (read < to_write || written < to_write) {
        if (written < to_write && (CRYP_SR & CRYP_SR_IFNF)) { // If we can write:
            if (written + 3 < in_len) { // And can do a full 32 bits:
                CRYP_DIN = *(uint32_t*)inp;
                inp += 4;
                written += 4;
            } else if (written < in_len) { // And we have < 32 bits
                auto remaining = in_len - written;
                assert(remaining <= sizeof(uint32_t));
                uint32_t final_32b = 0;
                memcpy(&final_32b, inp, remaining);
                CRYP_DIN = final_32b;
                written += 4;
            } else { // And we have to 0-pad to fill a block
                CRYP_DIN = 0;
                written += 4;
            }
        }

        if ((CRYP_SR & CRYP_SR_OFNE) && read < to_write) { // If we can read, do
            uint32_t read_32b = CRYP_DOUT; // Read a full 32b
            read += 4;
            auto read_8b = (uint8_t *)&read_32b; // Handy cast
            for (uint_fast8_t i = 0; i < 4; i++) { // Read as many bytes as we want from there
                if (outp_offset >= out_len) break;

                outp[outp_offset] = read_8b[i];
                outp_offset++;
                if (out_wrap && outp_offset >= out_len) outp_offset = 0;
            }
        }
    }
}

static void ccm_cbc_mac_hw(const uint8_t *key, const size_t key_len,
                           const uint8_t *msg, size_t msg_len,
                           const size_t L,
                           const uint8_t *aad, const size_t aad_len,
                           const uint8_t *nonce, const uint8_t nonce_len,
                           std::array<uint8_t, 16> &tag, const size_t M) {
    assert(key_len == 16); // can be expanded in future
    assert(nonce_len == 15 - L);
    assert(L >= 2 && L <= 8);
    assert(aad_len == 0); // For now, this is just to do

    // Stop
    crypto_stop();

    // Set key
    crypto_set_key(CRYPTO_KEY_128BIT, key);

    // Set IV = 0
    {
        uint8_t iv_arr[16] {};
        crypto_set_iv(iv_arr);
    }

    // Select the CBC encryption chaining mode
    crypto_set_algorithm(ENCRYPT_AES_CBC);

    crypto_set_datatype(CRYPTO_DATA_8BIT);

    // Flush in/out FIFOs
    CRYP_CR |= CRYP_CR_FFLUSH;

    crypto_start();

    // Program in b0
    {
        bool AData = aad_len > 0;
        uint8_t b0[16] = {
            static_cast<uint8_t>((AData << 6) | (((M - 2) / 2) << 3) | (L - 1)), // Flags
            0
        };
        // Copy nonce to b0
        memcpy(b0 + 1, nonce, nonce_len);
        // Copy l(m) to b0
        const uint64_t lm_big_endian = intToBigEndian(msg_len);
        memcpy(b0 + 1 + nonce_len, ((uint8_t*)&lm_big_endian) + 8 - L, L);

        // Write in b0
        crypto_process_bytes(b0, 16, nullptr, 0, true);
    }

    // XXX: here is where I'd encode aad data, but we aren't doing that

    // Program in actual bytes
    crypto_process_bytes(msg, msg_len, tag.data(), tag.size(), true);

    // Aaand we're done
    crypto_stop();
}


static bool ccm_hw(const uint8_t *key, const size_t key_len,
            const uint8_t *msg, size_t msg_len,
            const size_t L,
            const uint8_t *aad, const size_t aad_len,
            const uint8_t *nonce, const uint8_t nonce_len,
            uint8_t *ciphertext,
            uint8_t *tag, const size_t tag_len) {
    assert(tag_len >= 4 && tag_len <= 16 && tag_len % 2 == 0);

    std::array<uint8_t, 16> tag_raw{};

    ccm_cbc_mac_hw(
        key, key_len,
        msg, msg_len,
        L,
        aad, aad_len,
        nonce, nonce_len,
        tag_raw, tag_len
        );
    // !!! The hardware increments exactly the lower 32 bits of the 'IV' (A_i blocks), equiv to a L of 4.
    // So if L>4, we won't actually use the full counter space
    assert(L <= 4);
    // XXX Should we also assert than msg_len < 2^(8*L)?

    // Do the CTR mode

    // Ensure we're stopped
    crypto_stop();

    // Set key
    crypto_set_key(CRYPTO_KEY_128BIT, key);

    // Set IV = A_0
    {
        uint8_t a0[16] {};
        a0[0] = static_cast<uint8_t>(L - 1); // Flags
        // Copy nonce to a0
        memcpy(a0 + 1, nonce, nonce_len);
        crypto_set_iv(a0);
    }

    // Select the CBC encryption chaining mode
    crypto_set_algorithm(ENCRYPT_AES_CTR);

    crypto_set_datatype(CRYPTO_DATA_8BIT);

    // Flush in/out FIFOs
    CRYP_CR |= CRYP_CR_FFLUSH;

    crypto_start();

    // First, encrypt the tag.
    crypto_process_bytes(tag_raw.data(), tag_raw.size(), tag, tag_len, false);

    // Next, encrypt the main data.
    crypto_process_bytes(msg, msg_len, ciphertext, msg_len, false);

    crypto_stop();
    return true;
}

bool Platform::Crypto::AES128CCM(const std::array<uint8_t, AES128_KEY_SIZE> &key, const std::array<uint8_t, 13> &nonce, const uint8_t *msg, size_t msg_len, uint8_t *ciphertext, std::array<uint8_t, 16> &tag) {
    // Nonce shall be (at least partially) a counter - if a nonce gets reused, can simply XOR to break crypto
    // Random values fail due to birthday problem
    // Counter also gives replay protection

    static_assert(AES128_KEY_SIZE == 16 || AES128_KEY_SIZE == 24 || AES128_KEY_SIZE == 32);

    // L - length of the message length encoding. In interval [2,8], and gives a max message size of 2^(8*L) bytes.
    // We will only be using shorter messages, so this is fine for us.
    const size_t L = 2;
    const size_t max_msg_len = 65536; // = 2^(8*L) = 2^16
    if (msg_len > max_msg_len) return false;
    const uint8_t *additional_authed_data = nullptr;
    const size_t additional_authed_data_len = 0;
    assert(nonce.size() == 15 - L);

    ccm_hw(
        key.data(), key.size(),
        msg, msg_len,
        L,
        additional_authed_data, additional_authed_data_len,
        nonce.data(), nonce.size(),
        ciphertext,
        tag.data(), tag.size()
        );

    return true;
}