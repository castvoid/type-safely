#pragma once

#include <stdint.h>
#include <cstdlib>
#include <array>

namespace Platform {
    using Pin = uint64_t;

    class SerialPort {
    public:
        SerialPort();
        void begin(uint32_t baud_bps) const;
        void write(uint8_t c) const;
        void write(const char *str) const;
        bool hasDataAvailable() const;
        uint8_t readByte() const;
        uint16_t readByteIfAvailable() const;
    };
}

namespace Platform {
    void SetupAll();

    namespace Time {
        void Setup();
        void DelayMillis(uint32_t msec);
        void DelayMicros(uint32_t usec);
        uint32_t TimeMillis();
        uint32_t TimeMicros();
    }

    namespace Pins {
        typedef enum {
            kPinModeInput,
            kPinModeOutput,
            kPinModeOutputOpenDrain,
        } PinMode;

        void Setup();
        bool ReadPin(Pin pin);
        void WritePin(Pin pin, bool value);
        void TogglePin(Pin pin);
        void SetPinMode(Pin pin, PinMode mode);

        extern const Pin PinLED;
        extern const Pin PinButton;
    }

    namespace Crypto {
        void Setup();
        bool GetRandomBytes(uint8_t *buf, size_t len);
        namespace ECC {
            bool GenerateKeyPair(std::array<uint8_t, 32> &key_private, std::array<uint8_t, 32> &key_public);
            bool DeriveDHKey(const std::array<uint8_t, 32> &key_private, const std::array<uint8_t, 32> &key_public, std::array<uint8_t, 32> &dhkey);
        }
        bool AES128CMAC(const std::array<uint8_t, 16> &key, const uint8_t *msg, size_t msg_len, std::array<uint8_t, 16> &mac);
        bool AES128CCM(const std::array<uint8_t, 16> &key, const std::array<uint8_t, 13> &nonce, const uint8_t *msg, size_t msg_len, uint8_t *ciphertext, std::array<uint8_t, 16> &tag);
    }

    namespace Serial {
        void Setup();
        extern Platform::SerialPort SerialPort1;
    }

    namespace USBKeyboardDevice {
        typedef enum {
            USB_DEVICE_DISCONNECTED,
            USB_DEVICE_CONNECTED,
        } ConnectionStatus;

        void Setup();
        void Setup(void (*h)(ConnectionStatus));
        void SetHIDData(std::array<uint8_t, 8> &buf);
        void SetSingleKeyPressed(uint8_t key, uint8_t modifier);
        void SetSingleKeyPressed(uint8_t key);

        void WriteSecurePacket(uint8_t *buf, uint16_t len);
        void SetSecIfRXCallback(void (*rx_callback)(void *user_arg, uint8_t *buf, size_t len), void *user_arg = nullptr);

        uint32_t GetTimeLastTx();
    }

    namespace Power {
        void Setup();
        void Reboot();
        void JumpToDebugger();
        void JumpToBootloader();
    }

    namespace Atomic {
        void Setup();
        uint32_t EnterCritical();
        void ExitCritical(uint32_t old_state);
    }

    namespace EEPROM {
        void Setup();
        bool Write(uint16_t addr, const uint8_t *buf, size_t len);
        bool WritePage(uint16_t addr, const uint8_t *buf, size_t len);
        bool Read(uint16_t addr, uint8_t *buf, size_t len);
    }

    namespace Utils {
        void Setup();
        uint32_t CRC32(const uint8_t *buf, size_t buf_len);
    }
}
