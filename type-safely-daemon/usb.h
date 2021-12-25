
#pragma once

#include <stdint.h>

typedef void (*TSPUSBConnectionCallback)(bool connected, void *device, void *handle);

bool usb_setup(TSPUSBConnectionCallback connection_callback);
void usb_tick();
void usb_free_handle(void *handle);

int usb_write(void *handle, const uint8_t *buf, int len);
int usb_read(void *handle, uint8_t *buf, int len);
