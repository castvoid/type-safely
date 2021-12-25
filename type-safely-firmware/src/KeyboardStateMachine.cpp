//
// Created by Harry Jones on 24/01/2019.
//

#include <Platform.hpp>
#include "KeyboardStateMachine.hpp"
#include "SEGGER_RTT.h"
#include "ASCIIEncodedHIDParser.hpp"
#include "PersistentLTKStorage.hpp"
#include "debug.h"

#define TIME_INTERVAL_TIMEOUT 250
#define TIME_INTERVAL_SECIF_REPEAT 1

static void printhex(uint8_t *buf, size_t len) {
    (void)printhex; // supress unused func warning

    static constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    for (size_t i = 0; i < len; i++) {
        const auto byte = buf[i];

        const auto upper = (byte >> 4) & 0xF;
        const auto lower = byte & 0xF;
        SEGGER_RTT_Write(0, &(hexmap[upper]), 1);
        SEGGER_RTT_Write(0, &(hexmap[lower]), 1);
    }
}


// ==================================================
// SecureDelegate
bool KeyboardStateMachine::SecureDelegate::get_random_bytes(uint8_t *buf, size_t len) {
    return Platform::Crypto::GetRandomBytes(buf, len);
}

bool KeyboardStateMachine::SecureDelegate::does_recognise_id(std::array<uint8_t, 7> &id) {
    return PersistentLTKStorage::HaveLTKForEntityID(id);
}

bool KeyboardStateMachine::SecureDelegate::ltk_for_id(std::array<uint8_t, 7> &id, std::array<uint8_t, 16> &ltk) {
    return PersistentLTKStorage::GetLTKForEntityID(id, ltk);
}

bool KeyboardStateMachine::SecureDelegate::store_ltk_for_id(std::array<uint8_t, 7> &id, std::array<uint8_t, 16> &ltk) {
    return PersistentLTKStorage::SetLTKForEntityID(id, ltk);
}

bool KeyboardStateMachine::SecureDelegate::crypto_generate_ecdh_keypair(std::array<uint8_t, 32> &key_private,
                                                                        std::array<uint8_t, 32> &key_public) {
    return Platform::Crypto::ECC::GenerateKeyPair(key_private, key_public);
}

bool KeyboardStateMachine::SecureDelegate::crypto_derive_dhkey(const std::array<uint8_t, 32> &key_private,
                                                               const std::array<uint8_t, 32> &key_public,
                                                               std::array<uint8_t, 32> &dhkey) {
    return Platform::Crypto::ECC::DeriveDHKey(key_private, key_public, dhkey);
}

bool KeyboardStateMachine::SecureDelegate::crypto_aes_128_cmac(const std::array<uint8_t, 16> &key, const uint8_t *msg,
                                                               size_t msg_len, std::array<uint8_t, 16> &mac) {
    return Platform::Crypto::AES128CMAC(key, msg, msg_len, mac);
}

bool KeyboardStateMachine::SecureDelegate::crypto_aes_ccm_encrypt(const std::array<uint8_t, 16> &key,
                                                                  const std::array<uint8_t, 13> &nonce,
                                                                  const uint8_t *msg, size_t msg_len,
                                                                  uint8_t *ciphertext, std::array<uint8_t, 16> &tag) {
    return Platform::Crypto::AES128CCM(key, nonce, msg, msg_len, ciphertext, tag);
}

bool KeyboardStateMachine::SecureDelegate::begin_passkey_entry() {
    keyboard_sm->begin_passkey_entry();
    return true;
}

bool KeyboardStateMachine::SecureDelegate::get_entered_passkey(std::array<uint8_t, 16> &passkey) {
    return keyboard_sm->get_entered_passkey(passkey);
}

void KeyboardStateMachine::SecureDelegate::encrypted_session_began() {
    keyboard_sm->start_using_encryption();
}

void KeyboardStateMachine::SecureDelegate::encrypted_session_ended() {
    keyboard_sm->stop_using_encryption();
}


// ==================================================
// Keyboard state machine
static volatile bool connected = false;

static void inline blip() {
    Platform::Pins::WritePin(Platform::Pins::PinLED, true);
    Platform::Time::DelayMillis(25);
    Platform::Pins::WritePin(Platform::Pins::PinLED, false);
    Platform::Time::DelayMillis(25);
}

static void tick_secure_interface(TypeSafelyProtocol::DeviceStateMachine *device_ptr, uint8_t *in_buf = nullptr, size_t in_len = 0) {
    uint8_t out_buf[64] = {0};
    const auto state_old = device_ptr->getState();

    const auto generic_sm_pointer = static_cast<TypeSafelyProtocol::StateMachine *>(device_ptr);
    const auto out_msg_len = generic_sm_pointer->tick(in_buf, in_len, out_buf, sizeof(out_buf));

    const auto state_new = device_ptr->getState();
    if (state_old != state_new) {
        char msg[64] = {0};
        snprintf(msg, sizeof(msg), "%d -> %d\n", (int)state_old, (int)state_new);
        SEGGER_RTT_WriteString(0, msg);
    }

    if (out_msg_len < 0) {
        while (true) blip();
    } else if (out_msg_len > 0) {
//        SEGGER_RTT_WriteString(0, "Sent ");
//        printhex(out_buf, (size_t) out_msg_len);
//        SEGGER_RTT_WriteString(0, "\n");

        if (out_msg_len > UINT16_MAX) assert(false);
        Platform::USBKeyboardDevice::WriteSecurePacket(out_buf, static_cast<uint16_t>(out_msg_len));
    }
}

static void handle_new_msg(TypeSafelyProtocol::DeviceStateMachine *device_ptr, uint8_t *buf, size_t len) {
    // TODO: make function thread safe - this gets called from an interrupt

//    if (len > 0) {
//        SEGGER_RTT_WriteString(0, "Got ");
//        printhex(buf, len);
//        SEGGER_RTT_WriteString(0, "\n");
//    }
    tick_secure_interface(device_ptr, buf, len);
}

static void handle_connection_status(Platform::USBKeyboardDevice::ConnectionStatus status) {
    char buf[20] = {0};
    snprintf(buf, sizeof(buf), "Status: %d\n", status);
    SEGGER_RTT_WriteString(0, buf);

    connected = (status == Platform::USBKeyboardDevice::ConnectionStatus::USB_DEVICE_CONNECTED);
}


KeyboardStateMachine::KeyboardStateMachine() :
    tsp_sm(nullptr),
    mode(Mode::BootKeyboard),
    secure_delegate(this)
{};

void KeyboardStateMachine::setup() {
    // Not thread safe, but ok for this impl
    static bool have_setup = false;
    if (have_setup) return;
    have_setup = true;

    std::array<uint8_t, TypeSafelyProtocol::len_entity_id> secure_id{};
    PersistentLTKStorage::GetOwnID(secure_id);

    tsp_sm = static_cast<TypeSafelyProtocol::DeviceStateMachine *>(malloc(sizeof(TypeSafelyProtocol::DeviceStateMachine)));
    new (tsp_sm) TypeSafelyProtocol::DeviceStateMachine(secure_delegate, secure_id);

    Platform::USBKeyboardDevice::Setup(handle_connection_status);
    Platform::USBKeyboardDevice::SetSecIfRXCallback(
        reinterpret_cast<void (*)(void *, uint8_t *, size_t)>(handle_new_msg), this->tsp_sm);
}

void KeyboardStateMachine::tick() {
    if (!connected) {
        blip();
        return;
    }

    static uint32_t time_last_hid = 0;
    auto time_now = Platform::Time::TimeMillis();
    tick_secure_interface(this->tsp_sm);

    static auto serial_port = Platform::Serial::SerialPort1;
    static ASCIIEncodedHIDParser parser;

    if (mode == Mode::BootKeyboard) {
        static bool last_on = false;
        bool on = (Platform::Time::TimeMillis() & 0b1000000) != 0;
        if (on != last_on) {
            Platform::Pins::WritePin(Platform::Pins::PinLED, on);
            last_on = on;
        }
    } else {
        Platform::Pins::WritePin(Platform::Pins::PinLED, false);
    }

    uint16_t read = serial_port.readByteIfAvailable();
    if (read != 0) {
        // the read byte is stored in lower 8 bits
        auto c = static_cast<uint8_t>(read & 0xFF);

        // Parse this character
        auto d_array = parser.parse(c);
        // If this forms a complete USB HID msg, use it
        if (d_array.has_value()) {
            auto &hid = d_array.value();

            if (mode != Mode::SecureKeyboard) {
                // In secure mode, we only update every 1ms so they can't use timing to infer keys
                // so don't immediately send
                handle_new_hid(hid);
                time_last_hid = time_now;
            }

            hid_current = hid;
        }
    }

    // Repeat every 1ms

    if (mode == Mode::SecureKeyboard) {
        if (time_now > Platform::USBKeyboardDevice::GetTimeLastTx() + TIME_INTERVAL_TIMEOUT) {
            // If it's been TIME_INTERVAL_TIMEOUTms with no ack, downgrade ourselves
            SEGGER_RTT_WriteString(0, "timeout\n");
            tsp_sm->reset();
        } else if (time_now >= time_last_hid + TIME_INTERVAL_SECIF_REPEAT) {
            // In secure mode, we only update every TIME_INTERVAL_SECIF_REPEAT ms so they can't use timing to infer
            handle_new_hid(hid_current);
            time_last_hid = time_now;
        }
    }
}

void KeyboardStateMachine::handle_new_hid(std::array<uint8_t, 8> &hid) {
    static Mode last_mode = this->mode; // TODO

    if (mode != last_mode && last_mode == Mode::BootKeyboard) {
        Platform::USBKeyboardDevice::SetSingleKeyPressed(0);
    }

    switch (mode) {
        case Mode::BootKeyboard: {
            Platform::USBKeyboardDevice::SetHIDData(hid);
        } break;
        case Mode::PasskeyEntry: {
            auto parsed_number_opt = passkey_hid_parser.parse(hid);
            bool passkey_entry_complete = parsed_number_opt.has_value();
            if (passkey_entry_complete) {
                std::array<uint8_t, 16> p_arr{0};
                auto p = static_cast<uint32_t>(parsed_number_opt.value());
                for (size_t i = 0; i < sizeof(p); i++) {
                    p_arr[i] = static_cast<uint8_t>((p >> (i * 8)) & 0xFF);
                }

                entered_passkey = p_arr;
                mode = KeyboardStateMachine::Mode::BootKeyboard;
            }
        } break;
        case Mode::SecureKeyboard: {

            std::array<uint8_t, 64> packet_enc{};
            size_t packet_len;
            bool ok = tsp_sm->sessionEncryptPacket(hid, packet_enc, &packet_len); // TODO: handle failure
            if (ok) {
                Platform::USBKeyboardDevice::WriteSecurePacket(packet_enc.data(), static_cast<uint16_t>(packet_len));
            } else {
                assert(false);
            }
        }
    }
}

void KeyboardStateMachine::begin_passkey_entry() {
    entered_passkey = std::nullopt;
    passkey_hid_parser.reset(hid_current);
    mode = KeyboardStateMachine::Mode::PasskeyEntry;
}

bool KeyboardStateMachine::get_entered_passkey(std::array<uint8_t, 16> &passkey) {
    if (!entered_passkey.has_value()) return false;

    passkey = entered_passkey.value();
    entered_passkey = std::nullopt;

    return true;
}

void KeyboardStateMachine::start_using_encryption() {
    hid_current = {0};
    mode = KeyboardStateMachine::Mode::SecureKeyboard;
}

void KeyboardStateMachine::stop_using_encryption() {
    hid_current = {0};
    mode = KeyboardStateMachine::Mode::BootKeyboard;
}