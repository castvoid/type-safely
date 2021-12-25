#if defined(__linux__)
#include "HIDHandler.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <linux/uinput.h>
#include <cstring>
#include <assert.h>

// This array taken from linux source code - GPL licenced
// drivers/hid/usbhid/usbkbd.c

// The code in this file was based upon https://www.kernel.org/doc/html/v4.16/input/uinput.html

static const unsigned char usb_kbd_keycode[256] = {
        0,  0,  0,  0, 30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38,
        50, 49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44,  2,  3,
        4,  5,  6,  7,  8,  9, 10, 11, 28,  1, 14, 15, 57, 12, 13, 26,
        27, 43, 43, 39, 40, 41, 51, 52, 53, 58, 59, 60, 61, 62, 63, 64,
        65, 66, 67, 68, 87, 88, 99, 70,119,110,102,104,111,107,109,106,
        105,108,103, 69, 98, 55, 74, 78, 96, 79, 80, 81, 75, 76, 77, 71,
        72, 73, 82, 83, 86,127,116,117,183,184,185,186,187,188,189,190,
        191,192,193,194,134,138,130,132,128,129,131,137,133,135,136,113,
        115,114,  0,  0,  0,121,  0, 89, 93,124, 92, 94, 95,  0,  0,  0,
        122,123, 90, 91, 85,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        29, 42, 56,125, 97, 54,100,126,164,166,165,163,161,115,114,113,
        150,158,159,128,136,177,178,176,142,152,173,140
};

template<typename T> static inline bool buf_contains(const T needle, const T * haystack, size_t haystack_len) {
    for (size_t i = 0; i < haystack_len; i++) {
        const auto candidate = haystack[i];
        if (candidate == needle) return true;
    }

    return false;
}

static void emit(int fd, int type, int code, int val)
{
    struct input_event ie{};

    ie.type = type;
    ie.code = code;
    ie.value = val;
    /* timestamp values below are ignored */
    ie.time.tv_sec = 0;
    ie.time.tv_usec = 0;

    write(fd, &ie, sizeof(ie));
}


HIDHandler::HIDHandler() {
    hid_old = {0};
    fd = -1;
}

HIDHandler::~HIDHandler(){
    if (fd >= 0) {
        ioctl(fd, UI_DEV_DESTROY);
        close(fd);
    }
}

void HIDHandler::Setup() {
    struct uinput_setup usetup;

    fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) assert(false);

    ioctl(fd, UI_SET_EVBIT, EV_KEY);
    for (int i = 0; i < KEY_MAX; i++) {
        ioctl(fd, UI_SET_KEYBIT, i);
    }

    memset(&usetup, 0, sizeof(usetup));
    usetup.id.bustype = BUS_USB;
    usetup.id.vendor = 0x1234;
    usetup.id.product = 0x5678;
    strcpy(usetup.name, "Virtual keyboard");

    ioctl(fd, UI_DEV_SETUP, &usetup);
    ioctl(fd, UI_DEV_CREATE);
}

bool HIDHandler::HandleHIDData(const std::array<uint8_t, 8> &hid_new){
    if (fd < 0) {
        assert(false);
        return false;
    }

    //printf("GOT %02x %02x %02x %02x %02x %02x %02x %02x\n", hid_new[0], hid_new[1], hid_new[2], hid_new[3], hid_new[4], hid_new[5], hid_new[6], hid_new[7]);

    for (uint_fast8_t i = 0; i < 8; i++) {
        bool bit_new = ((hid_new[0] >> i) & 1) == 1;
        bool bit_old = ((hid_old[0] >> i) & 1) == 1;
        if (bit_new == bit_old) continue;

        emit(fd, EV_KEY, usb_kbd_keycode[i + 224], bit_new);
        emit(fd, EV_SYN, SYN_REPORT, 0);
    }

    for (uint_fast8_t i = 2; i < 8; i++) {
        if (hid_old[i] > 3 && !buf_contains(hid_old[i], hid_new.data() + 2, 6)) {
            if (usb_kbd_keycode[hid_old[i]]) {
                //printf("Released %d\n", hid_old[i]);
                emit(fd, EV_KEY, usb_kbd_keycode[hid_old[i]], 0);
                emit(fd, EV_SYN, SYN_REPORT, 0);
            } else {
                printf("Unknown key\n");
            }
        }

        if (hid_new[i] > 3 && !buf_contains(hid_new[i], hid_old.data() + 2, 6)) {
            if (usb_kbd_keycode[hid_new[i]]) {
                //printf("Pressed %d\n", hid_new[i]);
                emit(fd, EV_KEY, usb_kbd_keycode[hid_new[i]], 1);
                emit(fd, EV_SYN, SYN_REPORT, 0);
            } else {
                printf("Unknown key\n");
            }
        }
    }

    hid_old = hid_new;

    return true;
}

void HIDHandler::Reset(){
    hid_old = {0};
}

#else
#include "HIDHandler.hpp"

HIDHandler::HIDHandler() {
    fprintf(stderr, "WARNING: using printf rather than native keyboard input\n");
}

HIDHandler::~HIDHandler(){
}

void HIDHandler::Setup() {
}

bool HIDHandler::HandleHIDData(const std::array<uint8_t, 8> &hid_new){
    static std::remove_const<typeof(hid_new)>::type last_hid{0x00, 0x01, 0x00}; // Hack - 2nd byte is reserved in USB

    if (last_hid == hid_new) return true;

    printf("[SEC] Got %02x %02x %02x %02x %02x %02x %02x %02x\n", hid_new[0], hid_new[1], hid_new[2], hid_new[3], hid_new[4], hid_new[5], hid_new[6], hid_new[7]);
    last_hid = hid_new;

    return true;
}

void HIDHandler::Reset(){
}

#endif
