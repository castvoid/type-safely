cmake_minimum_required(VERSION 3.12)
project(proto_test_cpp)

set(CMAKE_CXX_STANDARD 17)

add_executable(proto_test_cpp
        curve25519_donna.c
        crypto.h
        main.cpp
        ../protocol_state_machine/tsp_device_state_machine.cpp
        ../protocol_state_machine/tsp_host_state_machine.cpp
        ../protocol_state_machine/tsp_state_machine.cpp
        ../protocol_state_machine/pb_common.c
        ../protocol_state_machine/pb_decode.c
        ../protocol_state_machine/pb_encode.c
        ../protocol_state_machine/messages.pb.c
        ../protocol_state_machine/messages-connection.pb.c
        ../protocol_state_machine/messages-pairing.pb.c
        ../protocol_state_machine/messages-session.pb.c
        ../protocol_state_machine/tsp_implementation_helpers.cpp)

target_include_directories(
        proto_test_cpp
        PRIVATE
        ../protocol_state_machine
)

if (APPLE)
        set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
endif()

target_compile_options(proto_test_cpp PRIVATE -Wall -Wunused-result)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(proto_test_cpp ${OPENSSL_LIBRARIES})
