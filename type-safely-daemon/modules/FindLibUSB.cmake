# FindLibUSB.cmake
# Once done this will define
#
#  LIBUSB_FOUND - System has libusb
#  LIBUSB_INCLUDE_DIR - The libusb include directory
#  LIBUSB_LIBRARY - The libraries needed to use libusb
#  LIBUSB_DEFINITIONS - Compiler switches required for using libusb
# Taken from https://github.com/texane/stlink/blob/master/cmake/modules/FindLibUSB.cmake
# Copyright (c) 2011 The stlink project (github.com/texane/stlink) contributors.
#                    All rights reserved.
# Copyright (c) 2011 The "Capt'ns Missing Link" Authors. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# 
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials provided
#      with the distribution.
#    * Neither the name of Martin Capitanio nor the names of its
#      contributors may be used to endorse or promote products derived
#      from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

if(WIN32 OR CMAKE_VS_PLATFORM_NAME OR MINGW OR MSYS)
	find_package(7Zip REQUIRED)

	set(LIBUSB_WIN_VERSION 1.0.21)
	set(LIBUSB_WIN_ARCHIVE libusb-${LIBUSB_WIN_VERSION}.7z)
	set(LIBUSB_WIN_ARCHIVE_PATH ${CMAKE_BINARY_DIR}/${LIBUSB_WIN_ARCHIVE})
	set(LIBUSB_WIN_OUTPUT_FOLDER ${CMAKE_BINARY_DIR}/3thparty/libusb-${LIBUSB_WIN_VERSION})

	if(EXISTS ${LIBUSB_WIN_ARCHIVE_PATH})
		message(STATUS "libusb archive already in build folder")
	else()
		message(STATUS "downloading libusb ${LIBUSB_WIN_VERSION}")
		file(DOWNLOAD
			https://sourceforge.net/projects/libusb/files/libusb-1.0/libusb-${LIBUSB_WIN_VERSION}/libusb-${LIBUSB_WIN_VERSION}.7z/download
			${LIBUSB_WIN_ARCHIVE_PATH}
		)
	endif()
	file(MAKE_DIRECTORY ${LIBUSB_WIN_OUTPUT_FOLDER})
	execute_process(COMMAND ${ZIP_EXECUTABLE} x -y ${LIBUSB_WIN_ARCHIVE_PATH} -o${LIBUSB_WIN_OUTPUT_FOLDER})
endif()

# FreeBSD
if (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
	FIND_PATH(LIBUSB_INCLUDE_DIR NAMES libusb.h
	HINTS
	/usr/include
	)
else ()
	FIND_PATH(LIBUSB_INCLUDE_DIR NAMES libusb.h
	HINTS
	/usr
	/usr/local
	/opt
	${LIBUSB_WIN_OUTPUT_FOLDER}/include
	PATH_SUFFIXES libusb-1.0
	)
endif()

if (APPLE)
	set(LIBUSB_NAME libusb-1.0.a)
elseif(MSYS OR MINGW)
	set(LIBUSB_NAME usb-1.0)
elseif(WIN32 OR CMAKE_VS_PLATFORM_NAME)
	set(LIBUSB_NAME libusb-1.0.lib)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
	set(LIBUSB_NAME usb)
else()
	set(LIBUSB_NAME usb-1.0)
endif()

if (MSYS OR MINGW)
	if (CMAKE_SIZEOF_VOID_P EQUAL 8)
		find_library(LIBUSB_LIBRARY NAMES ${LIBUSB_NAME}
			HINTS ${LIBUSB_WIN_OUTPUT_FOLDER}/MinGW64/static)
	else ()
		find_library(LIBUSB_LIBRARY NAMES ${LIBUSB_NAME}
			HINTS ${LIBUSB_WIN_OUTPUT_FOLDER}/MinGW32/static)
	endif ()
elseif(CMAKE_VS_PLATFORM_NAME)
	if (CMAKE_SIZEOF_VOID_P EQUAL 8)
		find_library(LIBUSB_LIBRARY NAMES ${LIBUSB_NAME}
			HINTS ${LIBUSB_WIN_OUTPUT_FOLDER}/MS64/dll)
	else ()
		find_library(LIBUSB_LIBRARY NAMES ${LIBUSB_NAME}
			HINTS ${LIBUSB_WIN_OUTPUT_FOLDER}/MS32/dll)
	endif ()
else()
	find_library(LIBUSB_LIBRARY NAMES ${LIBUSB_NAME}
	HINTS
	/usr
	/usr/local
	/opt)
endif ()

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Libusb DEFAULT_MSG LIBUSB_LIBRARY LIBUSB_INCLUDE_DIR)

mark_as_advanced(LIBUSB_INCLUDE_DIR LIBUSB_LIBRARY)