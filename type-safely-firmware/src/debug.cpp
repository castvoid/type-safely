#include <libopencm3/stm32/gpio.h>

#include <cassert>
#include <Platform.hpp>
#include "debug.h"

const auto port = GPIOB;
const uint16_t pins = (1 << 15) | (1 << 14) | (1 << 13) | (1 << 12) | (1 << 11) | (1 << 10);

extern "C" {
    void debug_enable() {
        gpio_mode_setup(port, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, pins);
        gpio_set_output_options(port, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, pins);
    }

    void set_debug_code(uint8_t code) {
        //assert(code == (code & 0b111111));

        gpio_clear(port, pins);
        gpio_set(port, code << 10);
    }
}