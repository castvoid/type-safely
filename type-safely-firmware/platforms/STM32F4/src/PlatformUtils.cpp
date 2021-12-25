#include "Platform.hpp"
#include <libopencm3/stm32/crc.h>
#include <cifra/tassert.h>
#include <cstring>
#include <libopencm3/stm32/rcc.h>

void Platform::Utils::Setup() {
    rcc_periph_clock_enable(RCC_CRC);
}

uint32_t Platform::Utils::CRC32(const uint8_t *buf, const size_t buf_len) {
    // Reset the onboard CRC computation thingy
    CRC_CR |= CRC_CR_RESET;

    const auto buf_32 = reinterpret_cast<const uint32_t *>(buf);
    const auto buf_32_len = buf_len / 4;
    for (size_t i = 0; i < buf_32_len; i++) {
        CRC_DR = buf_32[i]; // add this word to the CRC calculation
    }

    const size_t remainder = buf_len % 4;
    if (remainder != 0) {
        assert(remainder < 4);

        // Fill in the first <remainder> bytes of extra_word with the last <remainder> bytes of buf
        uint32_t exta_word = 0;
        const uint8_t *buf_remaining = buf + buf_len - remainder;
        memcpy(&exta_word, buf_remaining, remainder);

        CRC_DR |= exta_word;
    }

    uint32_t ret = CRC_DR;

    // Reset the onboard CRC computation thingy again to be #secure maybe
    CRC_CR |= CRC_CR_RESET;

    return ret;
}