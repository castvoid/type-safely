#pragma once

#include <vector>
#include <array>
#include <cassert>
#include <memory>
#include "messages.pb.h"

namespace TypeSafelyProtocol {
    const size_t len_private_key = 32;
    const size_t len_public_key = 32;
    const size_t len_entity_id = 7;
    const size_t len_dh_key = 32;
    const size_t len_pairing_nonce = 16;
    const size_t len_passkey = 16;
    const size_t len_commitment = 16;
    const size_t len_ltk = 16;
    const size_t len_mac_key = 16;
    const size_t len_session_key = 16;
    const size_t len_session_iv = 13;

    class StateMachine {
        public:
        struct StateMachineMemory {
            struct KeyPairs {
                std::array<uint8_t, len_private_key> private_host;
                std::array<uint8_t, len_public_key> public_host;
                std::array<uint8_t, len_private_key> private_device;
                std::array<uint8_t, len_public_key> public_device;
            };

            struct ConnectionSetupData {
                std::array<uint8_t, len_entity_id> id_host;
                std::array<uint8_t, len_entity_id> id_device;
                bool host_recognises_device_id;
                bool device_recognises_host_id;
            };

            struct PairingSetupData {
                KeyPairs keys;
                std::array<uint8_t, len_dh_key> dh_key;
                std::array<uint8_t, len_pairing_nonce> nonce_host;
                std::array<uint8_t, len_pairing_nonce> nonce_device;
                std::array<uint8_t, len_passkey> passkey_host;
                std::array<uint8_t, len_passkey> passkey_device;
                std::array<uint8_t, len_commitment> commitment_host;
                std::array<uint8_t, len_commitment> commitment_device;
                std::array<uint8_t, len_ltk> ltk;
                std::array<uint8_t, len_mac_key> mac_key;
            };

            struct SessionSetupData {
                KeyPairs keys;
            };

            std::array<uint8_t, len_session_key> session_key;
            std::array<uint8_t, len_session_iv> session_iv;
            uint64_t session_seq_num;
            ConnectionSetupData connection;
            PairingSetupData pairing;
            SessionSetupData session;
        };

        class IDelegate {
            public:
            virtual bool get_random_bytes(uint8_t *buf, size_t len) = 0;
            virtual bool does_recognise_id(std::array<uint8_t, len_entity_id> &id) = 0;
            virtual bool ltk_for_id(std::array<uint8_t, len_entity_id> &id, std::array<uint8_t, len_ltk> &ltk) = 0;
            virtual bool store_ltk_for_id(std::array<uint8_t, len_entity_id> &id, std::array<uint8_t, len_ltk> &ltk) = 0;
            virtual bool erase_ltk_for_id(std::array<uint8_t, len_entity_id> &id) { return false; };
            virtual bool crypto_generate_ecdh_keypair(std::array<uint8_t, len_private_key> &key_private,
                                                      std::array<uint8_t, len_public_key> &key_public) = 0;
            virtual bool crypto_derive_dhkey(const std::array<uint8_t, len_private_key> &key_private,
                                             const std::array<uint8_t, len_public_key> &key_public,
                                             std::array<uint8_t, len_dh_key> &dhkey) = 0;
            virtual bool crypto_aes_128_cmac(const std::array<uint8_t, 16> &key,
                                             const uint8_t *msg,
                                             size_t msg_len,
                                             std::array<uint8_t, 16> &mac) = 0;
            virtual bool crypto_aes_ccm_encrypt(const std::array<uint8_t, 16> &key, const std::array<uint8_t, 13> &nonce, const uint8_t *msg, size_t msg_len, uint8_t *ciphertext, std::array<uint8_t, 16> &tag) { assert(false); return false; };
            virtual bool crypto_aes_ccm_decrypt(const std::array<uint8_t, 16> &key, const std::array<uint8_t, 13> &nonce, const uint8_t *cipher_msg, size_t msg_len, uint8_t *plaintext, const std::array<uint8_t, 16> &tag) { assert(false); return false; };

            virtual void tsp_sm_received_error(const char *type) {};
            virtual void tsp_sm_encountered_error(const char *type) {};

            virtual void encrypted_session_began() {};
            virtual void encrypted_session_ended() {};

            // Host only
            virtual bool generate_display_passkey(std::array<uint8_t, len_passkey> &passkey) { assert(false); return false; };
            virtual void dismiss_passkey_display() { assert(false); };
            virtual void tsp_recieved_new_packet(std::array<uint8_t, 8> &packet) { assert(false); };
            virtual bool ready_to_begin_pairing() { assert(false); return false; }

            // Device only
            virtual bool begin_passkey_entry() { assert(false); return false; };
            virtual bool get_entered_passkey(std::array<uint8_t, len_passkey> &passkey) { assert(false); return false; };
        };


        explicit StateMachine(
            IDelegate &delegate,
            StateMachineMemory memory = {}
            ) : memory(memory)
              , delegate(delegate)
            {};

        virtual bool tick(const typesafely_protocol_MessageWrapper *in_msg_wrapper, typesafely_protocol_MessageWrapper &out_msg_wrapper) = 0;
        int32_t tick(const uint8_t *in_buf, size_t in_buf_len, uint8_t *out_buf, size_t out_buf_len);

    protected:
        StateMachineMemory memory;
        IDelegate &delegate;
    };

    namespace Utilities {
        bool BufToArr(const pb_bytes_array_t *buf, uint8_t *arr_data, size_t arr_len);
        bool ArrToBuf(const uint8_t *arr_data, size_t arr_len, pb_bytes_array_t *buf, size_t buf_max_len);
    }
}
