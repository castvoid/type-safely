#include <stdlib.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/usart.h>
#include <libopencm3/cm3/nvic.h>

#include "Platform.hpp"
#include "CircularBuffer.hpp"

#define USART_DEF USART6
#define USART_RCC_DEF RCC_USART6
#define USART_OUT_PORT GPIOC
#define USART_OUT_PIN GPIO6
#define USART_IN_PORT GPIOC
#define USART_IN_PIN GPIO7
#define USART_NVIC_IRQ NVIC_USART6_IRQ
#define USART_AF GPIO_AF8
#define USART_ISR_NAME usart6_isr

static CircularBuffer<uint8_t, 256> buf;

Platform::SerialPort::SerialPort() {}

void Platform::SerialPort::begin(uint32_t baud_bps) const {
    rcc_periph_clock_enable(USART_RCC_DEF);

    gpio_mode_setup(USART_OUT_PORT, GPIO_MODE_AF, GPIO_PUPD_NONE, USART_OUT_PIN);
    gpio_mode_setup(USART_IN_PORT, GPIO_MODE_AF, GPIO_PUPD_NONE, USART_IN_PIN);
    gpio_set_af(USART_OUT_PORT, USART_AF, USART_OUT_PIN);
    gpio_set_af(USART_IN_PORT, USART_AF, USART_IN_PIN);

    usart_set_baudrate(USART_DEF, baud_bps);
    usart_set_databits(USART_DEF, 8);
    usart_set_parity(USART_DEF, USART_PARITY_NONE);
    usart_set_stopbits(USART_DEF, USART_STOPBITS_1);
    usart_set_mode(USART_DEF, USART_MODE_TX_RX);
    usart_set_flow_control(USART_DEF, USART_FLOWCONTROL_NONE);

    nvic_enable_irq(USART_NVIC_IRQ);
    usart_enable_rx_interrupt(USART_DEF);
    usart_disable_error_interrupt(USART_DEF);

    usart_enable(USART_DEF);
}

void Platform::SerialPort::write(uint8_t c) const {
    usart_send_blocking(USART_DEF, c);
}

void Platform::SerialPort::write(const char *str) const {
    while (*str != '\0') {
        this->write(static_cast<uint8_t>(*str));
        str++;
    }
}

bool Platform::SerialPort::hasDataAvailable() const {
    return buf.isEmpty();
}

uint8_t Platform::SerialPort::readByte() const {
    while (buf.isEmpty()) {}

    uint8_t val = 0;
    buf.dequeue(&val);
    return val;
}

uint16_t Platform::SerialPort::readByteIfAvailable() const {
    if (buf.isEmpty()) return 0;

    uint8_t val = 0;
    buf.dequeue(&val);
    return ((uint16_t)0x0100) | val;
}

extern "C" {
    void USART_ISR_NAME(void) {
        auto sr = USART_SR(USART_DEF);
        if( (sr & USART_SR_RXNE) == 0) return;

        auto c = static_cast<const uint8_t>(usart_recv(USART_DEF));
        buf.queue(c);
    }
}
