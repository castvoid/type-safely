#include "Platform.hpp"
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>

#define GPIO_PORT_TYPE uint32_t

#define GPIO_NUM_TYPE uint16_t

#define GPIO_TO_PIN(port, pin) ( (((uint64_t)port) << 32) | pin )
#define PIN_TO_GPIO_NUM(gpio)  ( (GPIO_NUM_TYPE)(gpio & 0xFFFF) )
#define PIN_TO_GPIO_PORT(gpio) ( (GPIO_PORT_TYPE)(gpio >> 32) )


void Platform::Pins::Setup() {
    // Set up GPIO clocks
    rcc_periph_clock_enable(RCC_GPIOA);
    rcc_periph_clock_enable(RCC_GPIOB);
    rcc_periph_clock_enable(RCC_GPIOC);
    rcc_periph_clock_enable(RCC_GPIOD);
}

bool Platform::Pins::ReadPin(Platform::Pin pin) {
    const GPIO_PORT_TYPE port = PIN_TO_GPIO_PORT(pin);
    const GPIO_NUM_TYPE num = PIN_TO_GPIO_NUM(pin);

    return gpio_get(port, num) != 0;
}

void Platform::Pins::WritePin(Platform::Pin pin, bool value) {
    const GPIO_PORT_TYPE port = PIN_TO_GPIO_PORT(pin);
    const GPIO_NUM_TYPE num = PIN_TO_GPIO_NUM(pin);

    if (value) {
        gpio_set(port, num);
    } else {
        gpio_clear(port, num);
    }
}

void Platform::Pins::TogglePin(Platform::Pin pin) {
    const GPIO_PORT_TYPE port = PIN_TO_GPIO_PORT(pin);
    const GPIO_NUM_TYPE num = PIN_TO_GPIO_NUM(pin);

    gpio_toggle(port, num);
}

void Platform::Pins::SetPinMode(Platform::Pin pin, PinMode mode) {
    const GPIO_PORT_TYPE port = PIN_TO_GPIO_PORT(pin);
    const GPIO_NUM_TYPE num = PIN_TO_GPIO_NUM(pin);

    switch (mode) {
        case kPinModeInput:
            gpio_mode_setup(port, GPIO_MODE_INPUT, GPIO_PUPD_NONE, num);
            break;
        case kPinModeOutput:
            gpio_mode_setup(port, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, num);
            gpio_set_output_options(port, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, num);
            break;
        case kPinModeOutputOpenDrain:
            gpio_mode_setup(port, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, num);
            gpio_set_output_options(port, GPIO_OTYPE_OD, GPIO_OSPEED_50MHZ, num);
            break;
    }
}

const Platform::Pin Platform::Pins::PinLED = GPIO_TO_PIN(GPIOA, GPIO8);
const Platform::Pin Platform::Pins::PinButton = GPIO_TO_PIN(GPIOC, GPIO1);
