#pragma once

#include <libopencm3/usb/dwc/otg_fs.h>
#include <libopencm3/usb/usbd.h>
#include <libopencm3/usb/hid.h>

// ======================================
// Interface 1: Boot keyboard

#define USB_BKBD_EP 1
#define USB_BKBD_EP_ADDR_IN USB_ENDPOINT_ADDR_IN(USB_BKBD_EP)
// NOTE: this has to be EP 1 or 2 (empirically - reason unknown. cause of much pain)
// the boot keyboard is #1 so we take #2 here
#define USB_SECIF_ITR_EP_ADDR_IN USB_ENDPOINT_ADDR_IN(3)
#define USB_SECIF_BULK_EP_ADDR_OUT USB_ENDPOINT_ADDR_OUT(2)
#define USB_SECIF_BULK_EP_ADDR_IN USB_ENDPOINT_ADDR_IN(2)

static const uint8_t usb_bkbd_report_descriptor[] = {
    0x05, 0x01, // USAGE_PAGE (Generic Desktop)
    0x09, 0x06, // USAGE (Keyboard)
    0xa1, 0x01, // COLLECTION (Application)
    0x05, 0x07, // USAGE_PAGE (Keyboard)
    0x19, 0xe0, // USAGE_MINIMUM (Keyboard LeftControl)
    0x29, 0xe7, // USAGE_MAXIMUM (Keyboard Right GUI)
    0x15, 0x00, // LOGICAL_MINIMUM (0)
    0x25, 0x01, // LOGICAL_MAXIMUM (1)
    0x75, 0x01, // REPORT_SIZE (1)
    0x95, 0x08, // REPORT_COUNT (8)
    0x81, 0x02, // INPUT (Data,Var,Abs) //1 byte

    0x95, 0x01, // REPORT_COUNT (1)
    0x75, 0x08, // REPORT_SIZE (8)
    0x81, 0x03, // INPUT (Cnst,Var,Abs) //1 byte

    0x95, 0x06, // REPORT_COUNT (6)
    0x75, 0x08, // REPORT_SIZE (8)
    0x15, 0x00, // LOGICAL_MINIMUM (0)
    0x25, 0x65, // LOGICAL_MAXIMUM (101)
    0x05, 0x07, // USAGE_PAGE (Keyboard)
    0x19, 0x00, // USAGE_MINIMUM (Reserved (no event indicated))
    0x29, 0x65, // USAGE_MAXIMUM (Keyboard Application)
    0x81, 0x00, // INPUT (Data,Ary,Abs) //6 bytes

    0xc0, // END_COLLECTION
};

static const struct usb_endpoint_descriptor usb_bkbd_endpoints[] = {{
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress =  USB_BKBD_EP_ADDR_IN,
    .bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
    .wMaxPacketSize = 64,
    .bInterval = 1,
}};

typedef struct __attribute__((packed)) {
    struct usb_hid_descriptor hid_descriptor;
    struct {
        uint8_t bReportDescriptorType;
        uint16_t wDescriptorLength;
    } __attribute__((packed)) hid_report;
} usb_bkbd_hid_function_struct;

static const usb_bkbd_hid_function_struct usb_bkbd_hid_data = {
    .hid_descriptor = {
        .bLength = sizeof(usb_bkbd_hid_data),
        .bDescriptorType = USB_DT_HID,
        .bcdHID = 0x0110, // USB spec version
        .bCountryCode = 0, // No special localisation
        .bNumDescriptors = 1, // One
    },
    .hid_report = {
        .bReportDescriptorType = USB_DT_REPORT,
        .wDescriptorLength = sizeof(usb_bkbd_report_descriptor),
    }
};

static const struct usb_interface_descriptor usb_bkbd_interface = {
    .bLength = USB_DT_INTERFACE_SIZE,
    .bDescriptorType = USB_DT_INTERFACE,
    .bInterfaceNumber = 0,
    .bAlternateSetting = 0,
    .bNumEndpoints = 1,
    .bInterfaceClass = USB_CLASS_HID,
    .bInterfaceSubClass = 0x01, // = Keyboard
    .bInterfaceProtocol = 1,
    .iInterface = 4,
    .endpoint = usb_bkbd_endpoints,
    .extra = &usb_bkbd_hid_data,
    .extralen = sizeof(usb_bkbd_hid_data),
};

// ======================================
// Interface 2: Secure interface

static const struct usb_endpoint_descriptor usb_secif_endpoints[] = {
    {
        .bLength = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = USB_SECIF_ITR_EP_ADDR_IN,
        .bmAttributes = USB_ENDPOINT_ATTR_INTERRUPT,
        .wMaxPacketSize = 64,
        .bInterval = 1,
    },
    {
        .bLength = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = USB_SECIF_BULK_EP_ADDR_OUT,
        .bmAttributes = USB_ENDPOINT_ATTR_BULK,
        .wMaxPacketSize = 64,
    },
    {
        .bLength = USB_DT_ENDPOINT_SIZE,
        .bDescriptorType = USB_DT_ENDPOINT,
        .bEndpointAddress = USB_SECIF_BULK_EP_ADDR_IN,
        .bmAttributes = USB_ENDPOINT_ATTR_BULK,
        .wMaxPacketSize = 64,
    },
};


static const struct usb_interface_descriptor usb_secif_interface = {
    .bLength = USB_DT_INTERFACE_SIZE,
    .bDescriptorType = USB_DT_INTERFACE,
    .bInterfaceNumber = 1, // Index
    .bAlternateSetting = 0, // Value used to select this alt setting
    .bNumEndpoints = sizeof(usb_secif_endpoints)/sizeof(usb_secif_endpoints[0]),
    .bInterfaceClass = USB_CLASS_VENDOR, // = Vendor Specific
    .bInterfaceSubClass = 0x0, // = Vendor Specific
    .bInterfaceProtocol = 0x0, // = Vendor Specific
    .iInterface = 5, // Index of string descriptor describing this interface
    .endpoint = usb_secif_endpoints,
    .extra = 0,
    .extralen = 0,
};

// ======================================
// Device

static const struct usb_interface usb_ifaces[] = {
    {
        .num_altsetting = 1,
        .altsetting = &usb_bkbd_interface,
    },
    {
        .num_altsetting = 1,
        .altsetting = &usb_secif_interface,
    },
};

static const struct usb_config_descriptor usb_config_descriptors[] = {
    {
        .bLength = USB_DT_CONFIGURATION_SIZE, // Size in bytes
        .bDescriptorType = USB_DT_CONFIGURATION, // Configuration (const)
        .wTotalLength = 0, // Total length of data returned for this config
        .bNumInterfaces = (sizeof(usb_ifaces) / sizeof(usb_ifaces[0])),
        .bConfigurationValue = 1, // Value to use as arg to set config to select this config
        .iConfiguration = 0, // String number describing this config (0 = none)
        .bmAttributes = USB_CONFIG_ATTR_DEFAULT,
        .bMaxPower = 50, // Max power to use, as a multiple of 2mA
        .interface = usb_ifaces,
    }
};

static const char * const usb_strings[] = {
    "Harry Jones",
    "TypeSafely Keyboard",
    "[debug build]",
    "Boot keyboard interface",
    "Secure keyboard interface",
};

static const struct usb_device_descriptor usb_dev_descriptor = {
    .bLength = USB_DT_DEVICE_SIZE, // Descriptor size in bytes (= size of this struct)
    .bDescriptorType = USB_DT_DEVICE, // Type (constant, = "device")
    .bcdUSB = 0x0110, // USB spec number in BCD format (= USB 1.1)
    .bDeviceClass = 0, // Class code, assigned by USB-IF. 0x00 = vendor-defined
    .bDeviceSubClass = 0,
    .bDeviceProtocol = 0, // zero, so does not use class-specific protocols as a device. However, we may use class- specific protocols on an interface basis
    .bMaxPacketSize0 = 64, // Max packet size for endpoint 0. One of 8, 16, 32, or 64.
    .idVendor = 0xF055,
    .idProduct = 0x5D3E,
    .bcdDevice = 0x0200, // Device release number as BCD (from manufacturer)
    .iManufacturer = 1, // Index of string of manufacturer name
    .iProduct = 2, // Index of string of product name
    .iSerialNumber = 3, // Index of string of serial no
    .bNumConfigurations = sizeof(usb_config_descriptors) / sizeof(usb_config_descriptors[0]),
};
