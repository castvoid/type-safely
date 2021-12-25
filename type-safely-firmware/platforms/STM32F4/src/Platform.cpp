#include "Platform.hpp"

void Platform::SetupAll() {
    Platform::Time::Setup();
    Platform::Pins::Setup();
    Platform::Crypto::Setup();
    Platform::Serial::Setup();
    Platform::USBKeyboardDevice::Setup();
    Platform::Power::Setup();
    Platform::Atomic::Setup();
    Platform::EEPROM::Setup();
    Platform::Utils::Setup();
}
