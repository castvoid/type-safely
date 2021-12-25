#pragma once

#include <cstdint>
#include <array>

class HIDHandler {
protected:
    std::array<uint8_t, 8> hid_old;
    int fd;

public:
    explicit HIDHandler();
    ~HIDHandler();
    void Setup();
    bool HandleHIDData(const std::array<uint8_t, 8> &hid_new);
    void Reset();
};
