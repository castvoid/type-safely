#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
extern "C" {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wzero-length-array"
#pragma GCC diagnostic ignored "-Wpedantic"
#include <libusb.h>
#pragma GCC diagnostic pop
}
#include <assert.h>
#include <queue>
#include "usb.h"


#define KBD_VENDOR 0xF055
#define KBD_USB_ID 0x5D3E
#define KBD_CONFIG 0
#define KBD_NUM_INTERFACES 2
#define KBD_SEC_INTERFACE 1

static std::queue<std::pair<TSPUSBConnectionCallback, libusb_device*>> tick_dev_queue;

typedef struct {
    libusb_device_handle *device_handle;
    unsigned char ep_bulk_in;
    unsigned char ep_bulk_out;
    unsigned char ep_intr_in;
} TSPUSBHandle;


static libusb_device_handle *device_setup(libusb_device *dev,
                           unsigned char *kbd_itr_in_ep_addr_ptr,
                           unsigned char *kbd_bulk_out_ep_addr_ptr,
                           unsigned char *kbd_bulk_in_ep_addr_ptr) {
    int error = 0;
    const struct libusb_interface *interface = nullptr;
    struct libusb_config_descriptor *config = nullptr;
    libusb_device_handle *device_handle;

    if ((error = libusb_open(dev, &device_handle)) != 0) {
        fprintf(stderr, "Couldn't open device: got %d\n", error);
        return nullptr;
    }

    if (libusb_kernel_driver_active(device_handle, 0) != 0) {
        if (libusb_detach_kernel_driver(device_handle, 0)) {
            fprintf(stderr, "Couldn't detach kernel driver from keyboard interface!\n");
            goto fail;
        }
    }

    if ((error = libusb_set_configuration(device_handle, 1)) != 0) {
        fprintf(stderr, "Couldn't set configuration to %d: got %d\n", 1, error);
        goto fail;
    }

    if ((error = libusb_get_config_descriptor(dev, KBD_CONFIG, &config)) != 0) {
        fprintf(stderr, "Couldn't get configuration %d: got %d\n", KBD_CONFIG, error);
        goto fail;
    }

    if (config->bNumInterfaces != KBD_NUM_INTERFACES) {
        fprintf(stderr, "Unexpected number of interfaces: was %d, expected %d.\n", config->bNumInterfaces,
                KBD_NUM_INTERFACES);
        goto fail;
    }

    if ((error = libusb_claim_interface(device_handle, KBD_SEC_INTERFACE)) != 0) {
        fprintf(stderr, "Couldn't claim interface: %d\n", error);
        goto fail;
    }

    interface = &config->interface[KBD_SEC_INTERFACE];

    if (interface->num_altsetting != 1) {
        fprintf(stderr, "Unexpected number of alt-settings: expected 1, got %d\n", interface->num_altsetting);
        goto fail;
    }


    // Find correct endpoints
    {
        const struct libusb_interface_descriptor *interface_desc = &interface->altsetting[0];
        uint8_t found_endpoints = 0;
        for (uint8_t i = 0; i < interface_desc->bNumEndpoints; i++) {
            const struct libusb_endpoint_descriptor *endpoint = &interface_desc->endpoint[i];
            if ((endpoint->bmAttributes & 0b11) == LIBUSB_TRANSFER_TYPE_INTERRUPT &&
                (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_IN) == LIBUSB_ENDPOINT_IN) {
                *kbd_itr_in_ep_addr_ptr = endpoint->bEndpointAddress;
                if ((++found_endpoints) == 3) break;
            } else if ((endpoint->bmAttributes & 0b11) == LIBUSB_TRANSFER_TYPE_BULK) {
                if ((endpoint->bEndpointAddress & LIBUSB_ENDPOINT_IN) == LIBUSB_ENDPOINT_IN) {
                    *kbd_bulk_in_ep_addr_ptr = endpoint->bEndpointAddress;
                    if ((++found_endpoints) == 3) break;
                } else if ((endpoint->bEndpointAddress & LIBUSB_ENDPOINT_IN) == LIBUSB_ENDPOINT_OUT) {
                    *kbd_bulk_out_ep_addr_ptr = endpoint->bEndpointAddress;
                    if ((++found_endpoints) == 3) break;
                }
            }
        }

        if (found_endpoints != 3) {
            fprintf(stderr, "Couldn't find all endpoints on device.\n");
            goto fail;
        }
    }

    libusb_free_config_descriptor(config);

    return device_handle;

    fail:
    if (interface && device_handle) {
        libusb_release_interface(device_handle, KBD_SEC_INTERFACE);
        interface = nullptr;
    }

    if (config) {
        libusb_free_config_descriptor(config);
        config = nullptr;
    }

    if (device_handle) {
        libusb_close(device_handle);
        device_handle = nullptr;
    }

    return nullptr;
}

static int kbd_bulk_xfer(uint8_t *buf,
                         int len,
                         libusb_device_handle *dev_handle,
                         unsigned char endpoint_addr) {
    int recieved;
    const int timeout_ms = 10;

    // TODO: discards errors
    int error = libusb_bulk_transfer(
        dev_handle,
        endpoint_addr,
        buf,
        len,
        &recieved,
        timeout_ms
    );

    if (error != 0 && error != LIBUSB_ERROR_TIMEOUT) {
        fprintf(stderr, "LibUSB error %d when transferring bulk (ep = 0x%x)\n", error, endpoint_addr);
        return 0;
    };

    return recieved;
}

static int hotplug_callback(struct libusb_context *ctx, struct libusb_device *dev,
                     libusb_hotplug_event event, void *user_data) {
    auto callback = reinterpret_cast<TSPUSBConnectionCallback>(user_data);

    if (LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED == event) {
        tick_dev_queue.push(std::make_pair(callback, dev));
    } else if (LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT == event) {
        callback(false, dev, nullptr);
    } else {
        fprintf(stderr, "Unhandled libusb hotplug event %d\n", event);
    }

    return 0;
}

void usb_tick() {
    while (!tick_dev_queue.empty()) {
        auto [callback, dev] = tick_dev_queue.front();
        tick_dev_queue.pop();

        auto tsp_handle = new TSPUSBHandle;
        tsp_handle->device_handle = device_setup(
            dev,
            &tsp_handle->ep_intr_in,
            &tsp_handle->ep_bulk_out,
            &tsp_handle->ep_bulk_in
        );

        if (!tsp_handle->device_handle) {
            fprintf(stderr, "Unable to initialise device.");
            continue;
        }

        callback(true, dev, tsp_handle);
    }

    libusb_handle_events_completed(nullptr, nullptr);
}

bool usb_setup(TSPUSBConnectionCallback connection_callback) {
//    libusb_context *usb_context;

    int error;
    if ((error = libusb_init(nullptr)) != 0) {
        fprintf(stderr, "Failed to init USB context: %d\n", error);
        return false;
    }

    error = libusb_hotplug_register_callback(
        nullptr,
        (libusb_hotplug_event)(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT),
        LIBUSB_HOTPLUG_ENUMERATE,
        KBD_VENDOR,
        KBD_USB_ID,
        LIBUSB_HOTPLUG_MATCH_ANY,
        hotplug_callback,
        (void*)connection_callback,
        nullptr
    );

    if (error != LIBUSB_SUCCESS) {
        fprintf(stderr, "Error creating a hotplug callback\n");
        libusb_exit(nullptr);
        return false;
    }

    printf("USB setup complete\n");
    return true;
}

int usb_write(void *handle_void, const uint8_t *buf, int len) {
    auto handle = static_cast<TSPUSBHandle *>(handle_void);
    return kbd_bulk_xfer((uint8_t*)buf, len, handle->device_handle, handle->ep_bulk_out);
}

int usb_read(void *handle_void, uint8_t *buf, int len) {
    auto handle = static_cast<TSPUSBHandle *>(handle_void);
    return kbd_bulk_xfer(buf, len, handle->device_handle, handle->ep_bulk_in);
}

void usb_free_handle(void *handle_void) {
    auto handle = static_cast<TSPUSBHandle *>(handle_void);
    libusb_close(handle->device_handle);
    delete handle;
}
