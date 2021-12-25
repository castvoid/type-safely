# type-safely
_Cambridge Computer Science Tripos -- Part II_

Hardware USB keyloggers and programmable USB keystroke injection tools are widely available, inexpensive, and small enough to be easily concealable. Such devices can even be embedded inside a standard-size USB connector, making their detection nearly impossible. These devices allow the interception of sensitive details and the spoofing of keyboard input, so the threats to computer users can range from theft of sensitive information to the complete compromise of their computer.

This project aims to mitigate these threats by bringing the guarantees of confidentiality, integrity, authentication, and authorisation---provided by protocols such as TLS and Bluetooth---to communication with USB keyboards. This will be achieved by designing and implementing a new protocol, on top of the USB stack, for communication with USB keyboards.

In order to give a reasonable confidence in the security properties of the new protocol, the core of the cryptographic protocol will be based upon an existing, well-studied one, such as Bluetooth's \textit{Simple Secure Pairing}. The implementation will be made from scratch, and will consist of both software for the microcontroller inside the keyboards, and host-side drivers and keyboard management software for Ubuntu Linux.

## Building

#### Firmware
Make sure to have `gcc-arm-none-eabi` and GNU make installed.
```bash
cd type-safely-firmware
# Pull in libopencm3
git submodule init
git submodule update
# Run make on the libopencm3 directory
make -j8 -C ./libopencm3
# Make the project itself
make PLATFORM=STM32F4_1BITSY -j8
```
Edit: apply the fix at https://github.com/libopencm3/libopencm3/pull/794 to the libopencm3 dir before `make`ing it

#### C++ Protocol test
Make sure to have CMake, `libusb-1.0.0-dev`, and `libssl-dev` installed.
```bash
cd common/protobuf_test_cpp
mkdir build && cd build
cmake ..
make -j8
./proto_test_cpp
```

#### Host daemon
Similar to the C++ Protocol test. Requires Qt to be installed!
```bash
cd type-safely-daemon
mkdir build && cd build
cmake -DCMAKE_PREFIX_PATH=/Users/Harry/Qt5.12.0/5.12.0/clang_64/lib/cmake ..
make -j8
./typesafely_daemon
```
Note that you'll have to adjust CMAKE_PREFIX_PATH to match your installation directory.

Extra steps:
```bash
# [Linux only] Allow root to display windows on X
xhost +SI:localuser:root

# Make the LTK storage directory
sudo mkdir /etc/typesafely
sudo chmod -R 700 /etc/typesafely
```
