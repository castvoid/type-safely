#include "HIDtoNumberParser.hpp"
#include "SEGGER_RTT.h"

#include <assert.h>
#include <cstring>

extern "C" {
#include "USBKeyboardScancodes.h"
}

#define PARSED_NUMBER_DEFAULT 0
static const size_t HID_INDEX_KEYPRESSES_START = 2;
static const int8_t HID_GET_DIGIT_RETURN_UNKNOWN = -1;
static const int8_t HID_GET_DIGIT_RETURN_BACKSPACE = -2;
static const int8_t HID_GET_DIGIT_RETURN_ENTER = -3;


HIDtoNumberParser::HIDtoNumberParser() : parsed_number(PARSED_NUMBER_DEFAULT), last_keys({0}) {}


std::optional<int64_t> HIDtoNumberParser::parse(std::array<uint8_t, 8> &hid_data) {
    bool saw_return = false;

    // For each key in the new data:
    for (size_t i = HID_INDEX_KEYPRESSES_START; i < hid_data.size(); i++) {
        auto c = hid_data[i];
        if (c == 0) continue;

        // Check if the key was seen in the last message
        bool seen = false;
        for (auto other_key : last_keys) {
            if (c == other_key) {
                seen = true;
                break;
            }
        }

        if (!seen) {
            // If we didn't see the key, handle it as a newly pressed key, updating saw_return
            saw_return = handle_pressed_key(c) || saw_return;
        }
    }

    // Update last_keys
    assert(last_keys.size() + HID_INDEX_KEYPRESSES_START <= hid_data.size());
    memcpy(last_keys.data(), hid_data.data() + HID_INDEX_KEYPRESSES_START, last_keys.size());

    // If we saw the return key, return the number we saw so far
    if (saw_return) {
        int64_t ret = parsed_number;
        parsed_number = PARSED_NUMBER_DEFAULT;
        return ret;
    } else {
        return std::nullopt;
    }
}

static int8_t hid_get_digit_or_special(uint8_t key) {
    switch (key) {
        case USB_KEY_0:
        case USB_KEY_KEYPAD_0:
            return 0;
        case USB_KEY_1:
        case USB_KEY_KEYPAD_1:
            return 1;
        case USB_KEY_2:
        case USB_KEY_KEYPAD_2:
            return 2;
        case USB_KEY_3:
        case USB_KEY_KEYPAD_3:
            return 3;
        case USB_KEY_4:
        case USB_KEY_KEYPAD_4:
            return 4;
        case USB_KEY_5:
        case USB_KEY_KEYPAD_5:
            return 5;
        case USB_KEY_6:
        case USB_KEY_KEYPAD_6:
            return 6;
        case USB_KEY_7:
        case USB_KEY_KEYPAD_7:
            return 7;
        case USB_KEY_8:
        case USB_KEY_KEYPAD_8:
            return 8;
        case USB_KEY_9:
        case USB_KEY_KEYPAD_9:
            return 9;
        case USB_KEY_BACKSPACE:
            return HID_GET_DIGIT_RETURN_BACKSPACE;
        case USB_KEY_ENTER:
        case USB_KEY_KEYPAD_ENTER:
            return HID_GET_DIGIT_RETURN_ENTER;
        default:
            return HID_GET_DIGIT_RETURN_UNKNOWN;
    }
}

bool HIDtoNumberParser::handle_pressed_key(uint8_t key) {
    int8_t digit_or_special = hid_get_digit_or_special(key);

    bool key_was_digit = digit_or_special >= 0;
    if (key_was_digit) {
        assert(digit_or_special <= 9);
        parsed_number = (parsed_number * 10) + digit_or_special;
        return false;
    } else if (digit_or_special == HID_GET_DIGIT_RETURN_BACKSPACE) {
        parsed_number /= 10;
        return false;
    } else if (digit_or_special == HID_GET_DIGIT_RETURN_ENTER) {
        return true;
    } else {
        return false;
    }
}

void HIDtoNumberParser::reset() {
    last_keys = {0};
}

void HIDtoNumberParser::reset(std::array<uint8_t, 8> &hid_data) {
    last_keys = {hid_data[2], hid_data[3], hid_data[4], hid_data[5], hid_data[6], hid_data[7]};
}
