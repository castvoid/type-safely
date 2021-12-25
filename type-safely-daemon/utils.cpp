#include "utils.h"

static constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                  '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

std::string Utils::buf_to_hex(uint8_t *buf, size_t len) {
    std::string hex_str(len * 2, 'X');

    for (size_t i = 0; i < len; i++) {
        const auto byte = buf[i];

        const auto upper = (byte >> 4) & 0xF;
        const auto lower = byte & 0xF;
        hex_str[i*2] = hexmap[upper];
        hex_str[i*2 + 1] = hexmap[lower];
    }

    return hex_str;
}
