#include <stdint.h>
#include <libopencm3/cm3/scb.h>
#include <libopencm3/cm3/systick.h>

#include "Platform.hpp"

#define BLDR_ADDRESS 0x1FFF0000

void Platform::Power::Setup() {};

void Platform::Power::Reboot() {
    auto const cpu_restart_addr = (uint32_t *)0xE000ED0C; // Application Interrupt and Reset Control Register
    const uint32_t cpu_restart_val = 0x5FA0004; // SYSRESETREQ bit (not supported on all ARM Cortexes!)
    *cpu_restart_addr = cpu_restart_val;
}

void Platform::Power::JumpToDebugger() {
    asm volatile ("bkpt");
}

void Platform::Power::JumpToBootloader() {
    // TODO: doesn't work!

    SCB_VTOR = BLDR_ADDRESS & 0xFFFF;
    asm volatile("msr msp, %0"::"g" (*(volatile uint32_t *)BLDR_ADDRESS));
    auto jump = *(void (**)())(BLDR_ADDRESS + 4);
    jump();
}