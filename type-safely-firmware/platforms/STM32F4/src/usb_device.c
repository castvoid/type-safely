#include <stdlib.h>
#include <libopencm3/cm3/cortex.h>
#include <libopencm3/cm3/nvic.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/usb/dwc/otg_fs.h>
#include <libopencm3/usb/usbd.h>
#include <libopencm3/usb/hid.h>
#include <string.h>
#include <assert.h>

#include "usb_device.h"
#include "usb_device_config.h"
#include "SEGGER_RTT.h"
#include "PlatformTime_c.h"

uint8_t hid_buffer[8] = {0};
uint8_t usbd_control_buffer[128];
volatile usb_connection_status_t usb_connection_status;
static usbd_device *device;
static void (*connection_status_callback)(usb_connection_status_t new_status);
static void (*bulk_rx_callback)(void *user_arg, uint8_t *buf, size_t len);
static void *bulk_rx_callback_user_arg;
static uint32_t time_last_tx = 0;


static void set_connection_status(usb_connection_status_t new_status) {
    uint32_t interrrupt_state = cm_mask_interrupts(1);
    usb_connection_status = new_status;
    cm_mask_interrupts(interrrupt_state);

    connection_status_callback(new_status);
}

static enum usbd_request_return_codes hid_control_request(usbd_device *dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len, void (**complete)(usbd_device *dev, struct usb_setup_data *req)) {
    if(req->bmRequestType != (USB_REQ_TYPE_IN | USB_REQ_TYPE_INTERFACE) // data: dev to host. recipient: interface
        || req->bRequest != USB_REQ_GET_DESCRIPTOR
        || req->wValue != 0x2200 // Descriptor Type & Index: keyboard report descriptor
        ) {
        return USBD_REQ_NOTSUPP;
    }

    *buf = (uint8_t *)usb_bkbd_report_descriptor;
    *len = sizeof(usb_bkbd_report_descriptor);
    return USBD_REQ_HANDLED;
}

static void bulk_rx_callback_raw(usbd_device *usbd_dev, uint8_t ep) {
    assert(ep == USB_SECIF_BULK_EP_ADDR_OUT);

    uint8_t buf[65] = {0};

    size_t len = usbd_ep_read_packet(device, USB_SECIF_BULK_EP_ADDR_OUT, buf, sizeof(buf));
    if (len > 0 && bulk_rx_callback != NULL) {
        bulk_rx_callback(bulk_rx_callback_user_arg, buf, len);
    }
}

static void bulk_tx_callback_raw(usbd_device *usbd_dev, uint8_t ep) {
    time_last_tx = platform_time_millis();
}

static void handle_set_config(usbd_device *dev, uint16_t configValue) {

    usbd_ep_setup(dev, USB_BKBD_EP_ADDR_IN, USB_ENDPOINT_ATTR_INTERRUPT, 8, NULL);
//    usbd_ep_setup(dev, USB_SECIF_ITR_EP_ADDR_IN, USB_ENDPOINT_ATTR_INTERRUPT, 64, NULL);
    usbd_ep_setup(dev, USB_SECIF_BULK_EP_ADDR_OUT, USB_ENDPOINT_ATTR_BULK, 64, bulk_rx_callback_raw);
    usbd_ep_setup(dev, USB_SECIF_BULK_EP_ADDR_IN, USB_ENDPOINT_ATTR_BULK, 64, bulk_tx_callback_raw);

    usbd_register_control_callback(
        dev,
        USB_REQ_TYPE_STANDARD | USB_REQ_TYPE_INTERFACE,
        USB_REQ_TYPE_TYPE | USB_REQ_TYPE_RECIPIENT,
        hid_control_request
    );

    set_connection_status(USB_DEVICE_CONNECTED);
}

static void usb_device_handle_reset(void) {
    set_connection_status(USB_DEVICE_DISCONNECTED);
}

void set_hid_data(const uint8_t *buf) {
    uint32_t interrrupt_state = cm_mask_interrupts(1);
    memcpy(hid_buffer, buf, 8);
    cm_mask_interrupts(interrrupt_state);
}

void write_packet() {
    if (usb_connection_status != USB_DEVICE_CONNECTED) return;
    usbd_ep_write_packet(device, USB_BKBD_EP_ADDR_IN, hid_buffer, 8);
}

void otg_fs_isr(void) {
    if (!device) return;

    usbd_poll(device);
    write_packet();
}

uint16_t usbd_secif_bulk_write_packet(uint8_t *buf, uint16_t len) {
    if (usb_connection_status != USB_DEVICE_CONNECTED) return 0;
    return usbd_ep_write_packet(device, USB_SECIF_BULK_EP_ADDR_IN, buf, len);
}

void usbd_set_secif_bulk_rx_callback(void (*cb)(void *user_arg, uint8_t *buf, size_t len), void *user_arg) {
    bulk_rx_callback = cb;
    bulk_rx_callback_user_arg = user_arg;
}

usb_connection_status_t usbd_get_connection_status(void) {
    return usb_connection_status;
}

uint32_t usb_get_time_last_tx() {
    return time_last_tx;
}

void usb_init(void (*cs_cb)(usb_connection_status_t new_status)) {
    usb_connection_status = USB_DEVICE_DISCONNECTED;
    connection_status_callback = cs_cb;
    connection_status_callback(usb_connection_status);

    rcc_periph_clock_enable(RCC_GPIOA);
    rcc_periph_clock_enable(RCC_OTGFS);

    uint16_t gpios = GPIO9 | GPIO11 | GPIO12;
	gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, gpios);
	gpio_set_af(GPIOA, GPIO_AF10, gpios);

    device = usbd_init(
        &otgfs_usb_driver,
        &usb_dev_descriptor,
        usb_config_descriptors,
        usb_strings,
        sizeof(usb_strings) / sizeof(char *),
        usbd_control_buffer,
        sizeof(usbd_control_buffer)
    );

    usbd_register_set_config_callback(device, handle_set_config);
    usbd_register_reset_callback(device, usb_device_handle_reset);
    
    nvic_enable_irq(NVIC_OTG_FS_IRQ);
}
