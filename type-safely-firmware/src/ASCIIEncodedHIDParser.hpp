#pragma once

#include <stdint.h>
#include <array>
#include <optional>
#include "Platform.hpp"

static const char SEPARATOR = '-';

static int8_t parseHexChar(uint8_t c) {
    switch (c) {
        case '0': return 0x0;
        case '1': return 0x1;
        case '2': return 0x2;
        case '3': return 0x3;
        case '4': return 0x4;
        case '5': return 0x5;
        case '6': return 0x6;
        case '7': return 0x7;
        case '8': return 0x8;
        case '9': return 0x9;
        case 'a':
        case 'A': return 0xA;
        case 'b':
        case 'B': return 0xB;
        case 'c':
        case 'C': return 0xC;
        case 'd':
        case 'D': return 0xD;
        case 'e':
        case 'E': return 0xE;
        case 'f':
        case 'F': return 0xF;
        default: return -1;
    }
}

class ASCIIEncodedHIDParser {

protected:
    enum class State {
        Idle,
        ExpectingUpperByte,
        ExpectingLowerByte,
        ExpectingSeparator,
    };

    State CurrentState;
    std::array<uint8_t, 8> data;
    uint8_t pos;

public:
    explicit ASCIIEncodedHIDParser(): CurrentState(State::Idle), data(), pos(0) { }

    std::optional<std::array<uint8_t, 8>> parse(uint8_t c) {
        if (c == '\n' || c == '\r') {
            CurrentState = State::ExpectingUpperByte;
            data = { 0, 0, 0, 0, 0, 0, 0, 0 };
            pos = 0;
            return std::nullopt;
        }

        switch (CurrentState) {
            case State::Idle: {
                return std::nullopt;
            } break;

            case State::ExpectingUpperByte: {
                int8_t parsed = parseHexChar(c);
                if (parsed < 0) {
                    CurrentState = State::Idle;
                    return std::nullopt;
                }

                data[pos] |= parsed << 4;
                CurrentState = State::ExpectingLowerByte;
                return std::nullopt;
            } break;

            case State::ExpectingLowerByte: {
                int8_t parsed = parseHexChar(c);
                if (parsed < 0) {
                    CurrentState = State::Idle;
                    return std::nullopt;
                }

                data[pos] |= parsed;

                if (pos == data.size() - 1) {
                    CurrentState = State::Idle;
                    return data;
                }

                pos++;
                CurrentState = State::ExpectingSeparator;
                return std::nullopt;
            } break;

            case State::ExpectingSeparator: {
                if (c == SEPARATOR) {
                    CurrentState = State::ExpectingUpperByte;
                } else {
                    CurrentState = State::Idle;
                }
                return std::nullopt;
            } break;
        }

        return std::nullopt;
    }
};
