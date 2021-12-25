#include "tsp_host_state_machine.hpp"
#include "tsp_device_state_machine.hpp"

#include <stdlib.h>
#include <map>
#include <pb_encode.h>
#include "crypto.h"

static std::map<std::array<uint8_t, TypeSafelyProtocol::len_entity_id>, std::array<uint8_t, TypeSafelyProtocol::len_ltk>> ltk_storage;

// Single delegate for both ends of the protocol
static class : public TypeSafelyProtocol::StateMachine::IDelegate {
    bool get_random_bytes(uint8_t *buf, size_t len) override {
        return generate_random_bytes(buf, len);
    }

    bool does_recognise_id(std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id) override {
        return ltk_storage.find(id) != ltk_storage.end();
    }

    bool ltk_for_id(std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id, std::array<uint8_t, TypeSafelyProtocol::len_ltk> &ltk) override {
        auto val = ltk_storage.find(id);
        if (val == ltk_storage.end()) return false;

        ltk = val->second;
        return true;
    }

    bool store_ltk_for_id(std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id, std::array<uint8_t, TypeSafelyProtocol::len_ltk> &ltk) override {
        ltk_storage.insert_or_assign(id, ltk);
        return true;
    }

    bool crypto_generate_ecdh_keypair(std::array<uint8_t, TypeSafelyProtocol::len_private_key> &key_private, std::array<uint8_t, TypeSafelyProtocol::len_public_key> &key_public) override {
        return Crypto::generate_keypair(key_private, key_public);
    }

    bool crypto_derive_dhkey(const std::array<uint8_t, TypeSafelyProtocol::len_private_key> &key_private,
                             const std::array<uint8_t, TypeSafelyProtocol::len_public_key> &key_public,
                             std::array<uint8_t, TypeSafelyProtocol::len_dh_key> &dhkey) override {
        return Crypto::derive_dhkey(key_private, key_public, dhkey);
    }

    bool crypto_aes_128_cmac(const std::array<uint8_t, 16> &key,
                                 const uint8_t *msg,
                                 size_t msg_len,
                                 std::array<uint8_t, 16> &mac) override {
        return Crypto::compute_aes_128_cmac(key, msg, msg_len, mac);
    }

    bool begin_passkey_entry() override {
        return true;
    }

    bool get_entered_passkey(std::array<uint8_t, 16> &passkey) override {
        passkey = {0};
        passkey[0] = 123;
        return true;
    }

    bool generate_display_passkey(std::array<uint8_t, 16> &passkey) override {
        passkey = {0};
        passkey[0] = 123;
        return true;
    }
    void dismiss_passkey_display() override {}

    bool ready_to_begin_pairing() override {
        return true;
    }
} delegate;

int main() {
    std::array<uint8_t, TypeSafelyProtocol::len_entity_id> id_host = {1};
    std::array<uint8_t, TypeSafelyProtocol::len_entity_id> id_device = {2};

    auto host = TypeSafelyProtocol::HostStateMachine(delegate, id_host);
    auto device = TypeSafelyProtocol::DeviceStateMachine(delegate, id_device);

    uint8_t buffer[128];

    bool host_sent_message = false, device_sent_message = false;
    typesafely_protocol_MessageWrapper host_to_device{}, device_to_host{};

    setbuf(stdout, nullptr);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
    while (1) {
        auto host_old = host.getState();
        host_sent_message = host.tick(device_sent_message ? &device_to_host : nullptr, host_to_device);
        auto host_new = host.getState();
        if (host_old != host_new) printf("HST = %d -> %d\n", host_old, host_new);

        if (host_sent_message) {
            pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
            bool status = pb_encode(&stream, typesafely_protocol_MessageWrapper_fields, &host_to_device);
            size_t message_length = stream.bytes_written;
            if (status != 1) printf(" ENCODING FAILED");
            printf(" (msg len = %zu)\n", message_length);
        } else {
            if (host_old != host_new) printf("\n");
        }



        auto device_old = device.getState();
        device_sent_message = device.tick(host_sent_message ? &host_to_device : nullptr, device_to_host);
        auto device_new = device.getState();
        if (device_old != device_new) printf("DEV = %d -> %d\n", device_old, device_new);

        if (device_sent_message) {
            pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
            bool status = pb_encode(&stream, typesafely_protocol_MessageWrapper_fields, &device_to_host);
            size_t message_length = stream.bytes_written;
            if (status != 1) printf(" ENCODING FAILED");
            printf(" (msg len = %zu)\n", message_length);
        } else {
            if (device_old != device_new) printf("\n");
        }

        if (host_new == TypeSafelyProtocol::HostStateMachine::State::SessionOpen &&
            device_new == TypeSafelyProtocol::DeviceStateMachine::State::SessionOpen) {
            break;
        }
    }
#pragma clang diagnostic pop

    printf("Connection succeeded!\n");

    return 0;
}

