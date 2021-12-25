#pragma once

#include <stdint.h>
#include <stdio.h>

typedef enum {
    USB_DEVICE_DISCONNECTED,
    USB_DEVICE_CONNECTED
} usb_connection_status_t;

void usb_init(void (*cs_cb)(usb_connection_status_t new_status));
void set_hid_data(const uint8_t *buf);
usb_connection_status_t usbd_get_connection_status(void);
uint16_t usbd_secif_bulk_write_packet(uint8_t *buf, uint16_t len);
void usbd_set_secif_bulk_rx_callback(void (*cb)(void *user_arg, uint8_t *buf, size_t len), void *extra_arg);
uint32_t usb_get_time_last_tx();
