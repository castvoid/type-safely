#include "tsp_implementation_helpers.hpp"
#include "pb_decode.h"
#include "pb_encode.h"
#include <algorithm>
#include <cassert>


static void copy_array_with_counter_raw(uint8_t *dest_arr, size_t dest_len, const uint8_t *src_arr, size_t src_len, size_t *counter) {
    assert(*counter + src_len <= dest_len);

    memcpy(dest_arr + *counter, src_arr, src_len);
    *counter += src_len;
}

#define ARRAY_APPEND(dest, src, counter) copy_array_with_counter_raw(dest.data(), dest.size(), src.data(), src.size(), counter);


void crypto_ec_pubkey_get_x(const std::array<uint8_t, 65> &pubkey, std::array<uint8_t, 32> &x_coord) {
    std::copy_n(pubkey.begin() + 1, 32, x_coord.begin());
}

void crypto_ec_pubkey_get_x(const std::array<uint8_t, 33> &pubkey, std::array<uint8_t, 32> &x_coord) {
    std::copy_n(pubkey.begin() + 1, 32, x_coord.begin());
}

void crypto_ec_pubkey_get_x(const std::array<uint8_t, 32> &pubkey, std::array<uint8_t, 32> &x_coord) {
    x_coord = pubkey;
}

bool crypto_ble_f4(
    TypeSafelyProtocol::StateMachine::IDelegate &delegate,
    const std::array<uint8_t, 32> &u,
    const std::array<uint8_t, 32> &v,
    const std::array<uint8_t, 16> &x,
    const std::array<uint8_t, 16> &z,
    std::array<uint8_t, 16> &mac
) {
    // f4(U, V, X, Z) = AES-CMAC_X (U || V || Z)
    std::array<uint8_t, 80> message{};
    size_t counter = 0;
    ARRAY_APPEND(message, u, &counter);
    ARRAY_APPEND(message, v, &counter);
    ARRAY_APPEND(message, z, &counter);
    assert(message.size() == counter);

    return delegate.crypto_aes_128_cmac(x, message.data(), message.size(), mac);
}

bool crypto_ble_f5(
    TypeSafelyProtocol::StateMachine::IDelegate &delegate,
    const std::array<uint8_t, 32> &w,
    const std::array<uint8_t, 16> &n1,
    const std::array<uint8_t, 16> &n2,
    const std::array<uint8_t, 7> &a1,
    const std::array<uint8_t, 7> &a2,
    std::array<uint8_t, 16> &mac_upper,
    std::array<uint8_t, 16> &mac_lower
) {
    std::array<uint8_t, 16> t{};

    // Calculate key T
    {
        const std::array<uint8_t, 16> salt = {0x6C,0x88, 0x83,0x91, 0xAA,0xF5, 0xA5,0x38,
                                              0x60,0x37, 0x0B,0xDB, 0x5A,0x60, 0x83,0xBE};
        if (!delegate.crypto_aes_128_cmac(salt, w.data(), w.size(), t)) return false;
    }

    // Craft message = Counter=0|1 || key_id="btle" || N1 || N2 || A1 || A2 || Length=256
    const std::array<uint8_t, 4> param_key_id = {0x62, 0x74, 0x6c, 0x65}; // "btle"
    const std::array<uint8_t, 2> param_length = {0x01, 0x00}; // 256

    std::array<uint8_t, 53> message{0};
    size_t counter = 1; // 0 at message[0]
    ARRAY_APPEND(message, param_key_id, &counter);
    ARRAY_APPEND(message, n1, &counter);
    ARRAY_APPEND(message, n2, &counter);
    ARRAY_APPEND(message, a1, &counter);
    ARRAY_APPEND(message, a2, &counter);
    ARRAY_APPEND(message, param_length, &counter);
    assert(message.size() == counter);

    // CMAC with Counter=0 into mac_upper
    if (!delegate.crypto_aes_128_cmac(t, message.data(), message.size(), mac_upper)) return false;

    // CMAC with Counter=1 into mac_lower
    message[0] = 0x01;
    if (!delegate.crypto_aes_128_cmac(t, message.data(), message.size(), mac_lower)) return false;

    return true;
}

bool crypto_ble_f6(
    TypeSafelyProtocol::StateMachine::IDelegate &delegate,
    const std::array<uint8_t, TypeSafelyProtocol::len_mac_key> &mac_key,
    const std::array<uint8_t, TypeSafelyProtocol::len_pairing_nonce> &nonce_1,
    const std::array<uint8_t, TypeSafelyProtocol::len_pairing_nonce> &nonce_2,
    const std::array<uint8_t, TypeSafelyProtocol::len_passkey> &passkey,
    const std::array<uint8_t, 1> &recognises,
    const std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id_1,
    const std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id_2,
    std::array<uint8_t, 16> &mac
    ) {
    constexpr size_t expected_size = 2 * TypeSafelyProtocol::len_pairing_nonce + TypeSafelyProtocol::len_passkey + 1 + 2 * TypeSafelyProtocol::len_entity_id;
    std::array<uint8_t, expected_size> message{0};
    size_t counter = 0;
    ARRAY_APPEND(message, nonce_1, &counter);
    ARRAY_APPEND(message, nonce_2, &counter);
    ARRAY_APPEND(message, passkey, &counter);
    ARRAY_APPEND(message, recognises, &counter);
    ARRAY_APPEND(message, id_1, &counter);
    ARRAY_APPEND(message, id_2, &counter);
    assert(message.size() == counter);

    return delegate.crypto_aes_128_cmac(mac_key, message.data(), message.size(), mac);
}

bool crypto_gen_session_auth(
    TypeSafelyProtocol::StateMachine::IDelegate &delegate,
    const std::array<uint8_t, 16> &ltk,
    const std::array<uint8_t, 4> &role,
    const std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id_self,
    const std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id_other,
    const std::array<uint8_t, TypeSafelyProtocol::len_public_key> &pubkey,
    std::array<uint8_t, 16> &mac
    ) {
    constexpr size_t expected_message_len = 4 + 2*TypeSafelyProtocol::len_entity_id + TypeSafelyProtocol::len_public_key;
    std::array<uint8_t, expected_message_len> message{0};
    size_t counter = 0;
    ARRAY_APPEND(message, role, &counter);
    ARRAY_APPEND(message, id_self, &counter);
    ARRAY_APPEND(message, id_other, &counter);
    ARRAY_APPEND(message, pubkey, &counter);
    assert(message.size() == counter);

    return delegate.crypto_aes_128_cmac(ltk, message.data(), message.size(), mac);
}

bool crypto_generate_session_key(
    TypeSafelyProtocol::StateMachine::IDelegate &delegate,
    const std::array<uint8_t, TypeSafelyProtocol::len_private_key> &key_private,
    const std::array<uint8_t, TypeSafelyProtocol::len_public_key> &key_public,
    std::array<uint8_t, 16> &session_key,
    std::array<uint8_t, 13> &session_iv
    ) {
    const std::array<uint8_t, 16> salt = {0x12, 0x34, 0x56, 0xAC, 0x1D, 0x1C, 0x5A, 0x17,
                                          0x00, 0x68, 0x62, 0x67, 0x6A, 0x32, 0x00, 0x00};

    std::array<uint8_t, 33> dhkey_with_counter{0};
    {
        std::array<uint8_t, 32> dhkey{};
        if (!delegate.crypto_derive_dhkey(key_private, key_public, dhkey)) return false;
        static_assert(dhkey.size() >= 32);
        static_assert(dhkey_with_counter.size() -1 >= 32);
        memcpy(dhkey_with_counter.data() + 1, dhkey.data(), 32);
    }

    std::array<uint8_t, 16> session_iv_long{};
    bool cmac1_ok = delegate.crypto_aes_128_cmac(salt, dhkey_with_counter.data(), dhkey_with_counter.size(), session_key);
    dhkey_with_counter[0] = 1;
    bool cmac2_ok = delegate.crypto_aes_128_cmac(salt, dhkey_with_counter.data(), dhkey_with_counter.size(), session_iv_long);
    assert(session_iv.size() < session_iv_long.size());
    memcpy(session_iv.data(), session_iv.data(), session_iv.size());

    return cmac1_ok && cmac2_ok;
}

bool crypto_nonce_from_iv_and_seqnum(
    const std::array<uint8_t, 13> &iv,
    uint64_t seqnum,
    std::array<uint8_t, 13> &nonce
    ) {
    nonce = iv;

    static_assert(sizeof(seqnum) <= UINT_FAST8_MAX);
    const uint_fast8_t num_bytes_in_seqnum = sizeof(seqnum);
    assert(num_bytes_in_seqnum < nonce.size());

    for (uint_fast8_t i = 0; i < num_bytes_in_seqnum; i++) {
        nonce[i] ^= static_cast<uint8_t>(seqnum & 0xFF);
        seqnum >>= 8;
    }

    return true;
}

int encode_message(const typesafely_protocol_MessageWrapper &msg, uint8_t *out_buf, size_t out_buf_len, size_t *out_len) {
    pb_ostream_t stream = pb_ostream_from_buffer(out_buf, out_buf_len);
    bool status = pb_encode(&stream, typesafely_protocol_MessageWrapper_fields, &msg);

    if (!status) return -2;
    if (stream.bytes_written > INT32_MAX) return -3;
    *out_len = stream.bytes_written;

    return 1;
}

int decode_message(const uint8_t *in_buf, size_t in_len, typesafely_protocol_MessageWrapper &msg) {
    if (in_buf == nullptr) return -1;

    pb_istream_t stream_in = pb_istream_from_buffer(in_buf, in_len);
    bool status = pb_decode(&stream_in, typesafely_protocol_MessageWrapper_fields, &msg);
    if (!status) return -2;
    return 1;
}
