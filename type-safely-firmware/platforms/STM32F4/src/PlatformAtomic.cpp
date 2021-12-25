#include "Platform.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wregister"
#include <libopencm3/cm3/cortex.h>
#pragma GCC diagnostic pop

void Platform::Atomic::Setup() {
}

uint32_t Platform::Atomic::EnterCritical() {
    return cm_mask_interrupts(1);
}

void Platform::Atomic::ExitCritical(uint32_t old_state) {
    cm_mask_interrupts(old_state);
}
