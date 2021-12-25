#include "Platform.hpp"

#include <stdint.h>

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/i2c.h>
#include <libopencm3/stm32/f4/nvic.h>
#include <cassert>


/*
* The MIT License (MIT)
*
* This code based off eeprom_driver, Copyright (c) 2015 Marco Russi
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/



/* EEPROM address */
#define EEPROM_ADDRESS				0

/* Address byte to send */
#define ADDRESS_BYTE				((uint8_t)(0x50 | EEPROM_ADDRESS))


void Platform::EEPROM::Setup() {
    /* Enable GPIOB clock. */
    rcc_periph_clock_enable(RCC_GPIOB);
    /* set I2C1_SCL and I2C1_SDA, external pull-up resistors */
    gpio_mode_setup(GPIOB, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO8 | GPIO9);
    /* Open Drain, Speed 100 MHz */
    gpio_set_output_options(GPIOB, GPIO_OTYPE_OD, GPIO_OSPEED_100MHZ, GPIO8 | GPIO9);
    /* Alternate Function: I2C1 */
    gpio_set_af(GPIOB, GPIO_AF4,  GPIO8 | GPIO9);

    /* Enable I2C1 clock. */
    rcc_periph_clock_enable(RCC_I2C1);
    /* Enable I2C1 interrupt. */
    nvic_enable_irq(NVIC_I2C1_EV_IRQ);
    /* reset I2C1 */
    i2c_reset(I2C1);
    /* standard mode */
    i2c_set_standard_mode(I2C1);
    /* clock and bus frequencies */
    i2c_set_clock_frequency(I2C1, I2C_CR2_FREQ_2MHZ);
    i2c_set_ccr(I2C1, 20);
    /* enable error event interrupt only */
    i2c_enable_interrupt(I2C1, I2C_CR2_ITERREN);
    /* enable I2C */
    i2c_peripheral_enable(I2C1);
}

bool Platform::EEPROM::Write(uint16_t addr, const uint8_t *buf, size_t len) {
    // Pages wrap around every 64 bytes - the lower 6 bits of addr specify the position in the page, if you will
    // These 6 bits wrap around *inside* the page
    // What we want to do is to call WritePage for every page number s.t. the internal counter of addr never wraps

    if ((addr & 0b111111) != 0) {
        const uint16_t addr_inpage = addr & (uint16_t)0b111111;
        assert(addr_inpage < 64);
        size_t to_write = std::min(len, (size_t)((uint16_t)64 - addr_inpage));
        bool ok = WritePage(addr, buf, to_write);
        if (!ok) return false;

        buf += to_write;
        len -= to_write;
        addr = (addr + (uint16_t)0b1000000) & (uint16_t)(~0b111111);
    }

    assert((addr & 0b111111) == 0);

    while (len > 0) {
        size_t to_write = std::min(len, (size_t)64);
        bool ok = WritePage(addr, buf, to_write);
        if (!ok) return false;

        buf += to_write;
        len -= to_write;
        addr += to_write;
    }

    return true;
}

bool Platform::EEPROM::WritePage(uint16_t addr, const uint8_t *buf, size_t len) {
    if (len < 0) return false;
    if (len == 0) return true;

    bool success = true;

    bool got_ack = false;

    while (!got_ack) {
        /* send START and wait for completion */
        i2c_send_start(I2C1);
        while ((I2C_SR1(I2C1) & I2C_SR1_SB) == 0);

        /* send device address, r/w request and wait for completion */
        i2c_send_7bit_address(I2C1, ADDRESS_BYTE, I2C_WRITE);
        for (uint_fast16_t i = 0; i < 8192; i++) {
            if ((I2C_SR1(I2C1) & I2C_SR1_ADDR) != 0) {
                got_ack = true;
                break;
            }
        }
    }

    /* check SR2 and go on if OK */
    if ((I2C_SR2(I2C1) & I2C_SR2_MSL)		/* master mode */
        &&	(I2C_SR2(I2C1) & I2C_SR2_BUSY)) {	/* communication ongoing  */

        /* send memory address MSB */
        i2c_send_data(I2C1, static_cast<uint8_t>((addr >> 8) & 0xFF));
        while ((I2C_SR1(I2C1) & I2C_SR1_TxE) == 0);

        /* send memory address LSB */
        i2c_send_data(I2C1, static_cast<uint8_t>(addr & 0xFF));
        while ((I2C_SR1(I2C1) & I2C_SR1_TxE) == 0);

        /* write all bytes */
        while (len > 0) {
            /* send next data byte */
            i2c_send_data(I2C1, *buf);
            /* increment data buffer pointer and
             * decrement data buffer length */
            buf++;
            len--;
            while ((I2C_SR1(I2C1) & I2C_SR1_TxE) == 0);
        }
        /* send stop */
        i2c_send_stop(I2C1);

        /* ATTENTION: consider to wait for a while */
    } else {
        /* error */
        success = false;
    }

    return success;
}

bool Platform::EEPROM::Read(uint16_t addr, uint8_t *buf, size_t len) {
    if (len < 0) return false;
    if (len == 0) return true;

    bool success = true;

    /* send START and wait for completion */
    i2c_send_start(I2C1);
    while ((I2C_SR1(I2C1) & I2C_SR1_SB) == 0);

    /* send device address, write request and wait for completion */
    i2c_send_7bit_address(I2C1, ADDRESS_BYTE, I2C_WRITE);
    while ((I2C_SR1(I2C1) & I2C_SR1_ADDR) == 0);

    /* check SR2 and go on if OK */
    if ((I2C_SR2(I2C1) & I2C_SR2_MSL)		/* master mode */
        &&	(I2C_SR2(I2C1) & I2C_SR2_BUSY)) {	/* communication ongoing  */

        /* send memory address MSB */
        i2c_send_data(I2C1, static_cast<uint8_t>((addr >> 8) & 0xFF));
        while ((I2C_SR1(I2C1) & I2C_SR1_TxE) == 0);

        /* send memory address LSB */
        i2c_send_data(I2C1, static_cast<uint8_t>(addr & 0xFF));
        while ((I2C_SR1(I2C1) & I2C_SR1_TxE) == 0);

        /* send START and wait for completion */
        i2c_send_start(I2C1);
        while ((I2C_SR1(I2C1) & I2C_SR1_SB) == 0);

        /* send device address, read request and wait for completion */
        i2c_send_7bit_address(I2C1, ADDRESS_BYTE, I2C_READ);
        while ((I2C_SR1(I2C1) & I2C_SR1_ADDR) == 0);

        /* if communication ongoing  */
        if (I2C_SR2(I2C1) & I2C_SR2_BUSY) {
            /* enable ACK */
            i2c_enable_ack(I2C1);
            /* read all bytes */
            while (len > 0) {
                /* read received byte */
                while ((I2C_SR1(I2C1) & I2C_SR1_RxNE) == 0);
                *buf = i2c_get_data(I2C1);
                /* increment data buffer pointer and
                 * decrement data buffer length */
                buf++;
                len--;
                /* if last byte is remaining */
                if (len == 1) {
                    /* disable ACK */
                    i2c_disable_ack(I2C1);
                }
            }
            /* send stop */
            i2c_send_stop(I2C1);
        } else {
            /* error */
            success = false;
        }
    } else {
        /* error */
        success = false;
    }

    return success;
}