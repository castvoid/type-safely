#include <cstdlib>
#include <cstdio>
#include <map>
#include <libopencm3/stm32/gpio.h>
#include <tsp_state_machine.hpp>
#include <tsp_device_state_machine.hpp>

#include "Platform.hpp"
#include "ASCIIEncodedHIDParser.hpp"
#include "SEGGER_RTT.h"
#include "KeyboardStateMachine.hpp"
#include "debug.h"
#include "PersistentLTKStorage.hpp"


extern "C" void __cxa_pure_virtual() { assert(false); }


static void setup(KeyboardStateMachine &kbd_sm) {
    Platform::Time::Setup();
    Platform::Pins::Setup();
    Platform::Crypto::Setup();
    Platform::EEPROM::Setup();
    Platform::Utils::Setup();
    PersistentLTKStorage::Setup();

    Platform::Pins::SetPinMode(Platform::Pins::PinButton, Platform::Pins::kPinModeInput);
    if (!Platform::Pins::ReadPin(Platform::Pins::PinButton)) {
        PersistentLTKStorage::Reset();
    }
    
    Platform::Pins::SetPinMode(Platform::Pins::PinLED, Platform::Pins::kPinModeOutput);
    Platform::Pins::WritePin(Platform::Pins::PinLED, 0);
    Platform::Time::DelayMillis(1000);

    kbd_sm.setup();
    Platform::Pins::WritePin(Platform::Pins::PinLED, 1);
}


int main(int argc, const char * argv[]) {
    SEGGER_RTT_WriteString(0, "Booting...\n");
    KeyboardStateMachine kbd_sm;
    setup(kbd_sm);
    debug_enable();

    SEGGER_RTT_WriteString(0, "Up!\n");

    auto serial_port = Platform::Serial::SerialPort1;
    serial_port.begin(115200);

    while (true) {
        kbd_sm.tick();
    }

    return 0;
}
