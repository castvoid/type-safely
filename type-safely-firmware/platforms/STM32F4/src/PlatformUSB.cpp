#include "Platform.hpp"
#include <stdlib.h>

extern "C" {
#include "usb_device.h"
}

static void emptyHandler(Platform::USBKeyboardDevice::ConnectionStatus s) {};
static void (*connection_status_handler)(Platform::USBKeyboardDevice::ConnectionStatus) = emptyHandler;
static void handlerPassthrough(usb_connection_status_t s) {
	Platform::USBKeyboardDevice::ConnectionStatus cs;

	switch (s) {
		case USB_DEVICE_DISCONNECTED:
			cs = Platform::USBKeyboardDevice::ConnectionStatus::USB_DEVICE_DISCONNECTED;
			break;
		case USB_DEVICE_CONNECTED:
			cs = Platform::USBKeyboardDevice::ConnectionStatus::USB_DEVICE_CONNECTED;
			break;
		default:
			abort();
	}

	connection_status_handler(cs);
}

namespace Platform::USBKeyboardDevice {
	void Setup() {
		Setup(emptyHandler);
	}

	void Setup(void (*h)(ConnectionStatus)) {
		connection_status_handler = h;
		usb_init(handlerPassthrough);
	}

	void SetHIDData(std::array<uint8_t, 8> &arr) {
        set_hid_data(arr.data());
	}

	void SetSingleKeyPressed(uint8_t key, uint8_t modifier) {
		std::array<uint8_t, 8> arr = { modifier, 0, key, 0, 0, 0, 0, 0 };
		SetHIDData(arr);
	}

	void SetSingleKeyPressed(uint8_t key) {
		SetSingleKeyPressed(key, 0);
	}

	volatile static int fails = 0;
	void WriteSecurePacket(uint8_t *buf, uint16_t len) {
		auto len_wrote = usbd_secif_bulk_write_packet(buf, len);
		if (len_wrote != len) {
			// TODO: DO SOMETHIN BAD (e.g., downgrade)
			fails++;
		}
	}

	void SetSecIfRXCallback(void (*bulk_rx_callback)(void *user_arg, uint8_t *buf, size_t len), void *user_arg) {
		usbd_set_secif_bulk_rx_callback(bulk_rx_callback, user_arg);
	}

	uint32_t GetTimeLastTx() {
	    return usb_get_time_last_tx();
	}
}
