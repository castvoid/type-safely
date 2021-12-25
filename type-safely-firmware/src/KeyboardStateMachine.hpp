#pragma once

#include <optional>
#include "tsp_device_state_machine.hpp"
#include "HIDtoNumberParser.hpp"

class KeyboardStateMachine {
public:
    explicit KeyboardStateMachine();

    void setup();
    void tick();

private:
    class SecureDelegate : public TypeSafelyProtocol::StateMachine::IDelegate {
    public:
        explicit SecureDelegate(KeyboardStateMachine *keyboard_sm) : keyboard_sm(keyboard_sm) {}
        bool get_random_bytes(uint8_t *buf, size_t len) override;
        bool does_recognise_id(std::array<uint8_t, 7> &id) override;
        bool ltk_for_id(std::array<uint8_t, 7> &id, std::array<uint8_t, 16> &ltk) override;
        bool store_ltk_for_id(std::array<uint8_t, 7> &id, std::array<uint8_t, 16> &ltk) override;
        bool crypto_generate_ecdh_keypair(std::array<uint8_t, 32> &key_private,
                                          std::array<uint8_t, 32> &key_public) override;
        bool crypto_derive_dhkey(const std::array<uint8_t, 32> &key_private, const std::array<uint8_t, 32> &key_public,
                                 std::array<uint8_t, 32> &dhkey) override;
        bool crypto_aes_128_cmac(const std::array<uint8_t, 16> &key, const uint8_t *msg, size_t msg_len,
                                 std::array<uint8_t, 16> &mac) override;
        bool crypto_aes_ccm_encrypt(const std::array<uint8_t, 16> &key, const std::array<uint8_t, 13> &nonce,
            const uint8_t *msg, size_t msg_len, uint8_t *ciphertext, std::array<uint8_t, 16> &tag) override;
        bool begin_passkey_entry() override;
        bool get_entered_passkey(std::array<uint8_t, 16> &passkey) override;
        void encrypted_session_began() override;
        void encrypted_session_ended() override;

    private:
        KeyboardStateMachine *keyboard_sm;
    };

    friend class SecureDelegate;

    enum class Mode {
        BootKeyboard,
        PasskeyEntry,
        SecureKeyboard,
    };

    TypeSafelyProtocol::DeviceStateMachine *tsp_sm;
    Mode mode;
    SecureDelegate secure_delegate;
    HIDtoNumberParser passkey_hid_parser;
    std::optional<std::array<uint8_t, TypeSafelyProtocol::len_passkey>> entered_passkey;
    std::array<uint8_t, 8> hid_current{};

    void handle_new_hid(std::array<uint8_t, 8> &hid);

    void begin_passkey_entry();
    bool get_entered_passkey(std::array<uint8_t, 16> &passkey);

    void start_using_encryption();
    void stop_using_encryption();
};

