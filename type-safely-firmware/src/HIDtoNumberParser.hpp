#pragma once

#include <stdint.h>
#include <array>
#include <optional>

/*
 * SetHID takes the current set of keys pressed as a USB HID message.
 * It looks for any numbers that are pressed, ignoring other keys with the exception of backspace and return.
 * Once a return key is encountered, SetHID returns the number
 *
 * HID format: modifier, reserved=0, key1, key2, key3, key4, key5, key6
 *             [0]       [1]         [2]   [3]   [4]   [5]   [6]   [7]
 *
 */
class HIDtoNumberParser {

protected:
    uint64_t parsed_number;
    std::array<uint8_t, 6> last_keys;
    bool handle_pressed_key(uint8_t key);

public:
    explicit HIDtoNumberParser();
    std::optional<int64_t> parse(std::array<uint8_t, 8> &hid_data);
    void reset();
    void reset(std::array<uint8_t, 8> &hid_data);
};
