cmake_minimum_required(VERSION 3.1.0)
project ( typesafely_daemon )

set(CMAKE_CXX_STANDARD 17)

# Find includes in corresponding build directories
set(CMAKE_INCLUDE_CURRENT_DIR ON)
# Instruct CMake to run moc automatically when needed
set(CMAKE_AUTOMOC ON)
# Create code from a list of Qt designer ui files
set(CMAKE_AUTOUIC ON)

set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-Os")

# Find the QtWidgets library
find_package(Qt5Widgets CONFIG REQUIRED)

set(typesafely_daemon_SRCS
    main.cpp usb.cpp utils.cpp
    crypto.cpp
    curve25519_donna.c
        pairingpage.cpp
        HIDHandler.cpp
        TSPPairingWizard.cpp TSPPairingWizard.hpp TSPGUIWorker.cpp TSPGUIWorker.hpp
        TSPGUIApplication.cpp TSPGUIApplication.hpp HIDLockdownManager.cpp
        HIDLockdownManager.hpp TSPPairingManager.cpp TSPPairingManager.hpp)

set(tsp_SOURCES
    ../common/protocol_state_machine/tsp_device_state_machine.cpp
    ../common/protocol_state_machine/tsp_host_state_machine.cpp
    ../common/protocol_state_machine/tsp_state_machine.cpp
    ../common/protocol_state_machine/pb_common.c
    ../common/protocol_state_machine/pb_decode.c
    ../common/protocol_state_machine/pb_encode.c
    ../common/protocol_state_machine/messages.pb.c
    ../common/protocol_state_machine/messages-connection.pb.c
    ../common/protocol_state_machine/messages-pairing.pb.c
    ../common/protocol_state_machine/messages-session.pb.c
    ../common/protocol_state_machine/tsp_implementation_helpers.cpp
        )

add_executable(typesafely_daemon ${typesafely_daemon_SRCS} ${tsp_SOURCES})

target_include_directories(
        typesafely_daemon
        PRIVATE
        ../common/protocol_state_machine
)

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_SOURCE_DIR}/modules")
target_link_libraries(typesafely_daemon Qt5::Widgets)

if (APPLE)
    find_library(CoreFoundation CoreFoundation)
    find_library(IOKit IOKit)
    target_link_libraries(typesafely_daemon ${CoreFoundation} ${IOKit})
    set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
endif()

find_package(LibUSB REQUIRED)
include_directories(${LIBUSB_INCLUDE_DIR})
target_link_libraries(typesafely_daemon ${LIBUSB_LIBRARY})
target_link_libraries(typesafely_daemon m)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(typesafely_daemon ${OPENSSL_LIBRARIES})
