ifneq ($(VERBOSE), 1)
	V := @
endif

all: hex

# Default, set for convenience.
PLATFORM ?= STM32F4_1BITSY

PROJECT ?= type-safely
BUILD_ROOT ?= build
OPENCM_PATH ?= libopencm3
PROTOBUF_PATH ?= ../common/protocol_state_machine

###############################################################################

BOARD = $(or $(word 2,$(subst _, ,$(PLATFORM))),$())
PLATFORM_SERIES = $(word 1,$(subst _, ,$(PLATFORM)))
PLATFORM_DIR = platforms/$(PLATFORM_SERIES)

BUILD_DIR ?= $(BUILD_ROOT)/$(PLATFORM)/firmware
INCLUDE_DIRS ?= $(OPENCM_PATH)/include src $(PLATFORM_DIR)/src $(PLATFORM_DIR)/external $(PROTOBUF_PATH)
SOURCE_DIRS ?= src $(PLATFORM_DIR)/src $(wildcard $(PLATFORM_DIR)/external/*) $(PROTOBUF_PATH)

###############################################################################

CPP_DEPFLAG ?= -MMD
CPPFLAGS += -Os
CPPFLAGS += -Wall -g $(CPP_DEPFLAG) -Wdouble-promotion -ffunction-sections -fdata-sections -nostdlib -finline-small-functions -findirect-inlining $(addprefix -I,$(INCLUDE_DIRS))
CXXFLAGS += -std=c++17 -felide-constructors -fno-exceptions -fno-rtti  -fno-threadsafe-statics
CFLAGS +=
LDFLAGS += -Wl,--gc-sections -lm -L$(OPENCM_PATH)/lib --specs=nosys.specs -nostartfiles

###############################################################################

C_FILES := $(foreach dir, $(SOURCE_DIRS), $(wildcard $(dir)/*.c))
CPP_FILES := $(foreach dir, $(SOURCE_DIRS), $(wildcard $(dir)/*.cpp))

SOURCE_OBJS := $(C_FILES:.c=.o) $(CPP_FILES:.cpp=.o)
OBJS := $(foreach file, $(SOURCE_OBJS), $(BUILD_DIR)/$(file))
DEPS := $(OBJS:.o=.d)

###############################################################################

COMPILER_PREFIX ?= arm-none-eabi-
CC = $(COMPILER_PREFIX)gcc
CXX = $(COMPILER_PREFIX)g++
OBJCOPY = $(COMPILER_PREFIX)objcopy

ifdef PLATFORM
include $(PLATFORM_DIR)/Makefile.inc
else
ifneq ($(MAKECMDGOALS), clean)
$(error PLATFORM must be defined)
endif
endif

###############################################################################

build: $(BUILD_DIR)/$(PROJECT).elf

hex: $(BUILD_DIR)/$(PROJECT).hex

bin: $(BUILD_DIR)/$(PROJECT).bin

$(BUILD_DIR)/%.o: %.c
	@mkdir -p "$(dir $@)"
	@echo "  CC      $@"
	$(V)"$(CC)" $(CPPFLAGS) $(CFLAGS) $(L_INC) -o "$@" -c "$<"

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p "$(dir $@)"
	@echo "  CXX     $@"
	$(V)"$(CXX)" $(CPPFLAGS) $(CXXFLAGS) $(L_INC) -o "$@" -c "$<"

$(BUILD_DIR)/$(PROJECT).elf: $(OBJS)
	@echo "  LD      $@"
	$(V)"$(CC)" -o "$@" $(OBJS) $(LDFLAGS)

%.hex: %.elf
	@echo "  OBJCOPY $@"
	$(V)"$(OBJCOPY)" -O ihex "$<" "$@"

%.bin: %.elf
	@echo "  OBJCOPY $@"
	$(V)"$(OBJCOPY)" -O binary "$<" "$@"

.PHONY:	clean
clean:
	@echo Cleaning...
	-$(V)rm -rf "$(BUILD_ROOT)"

-include $(DEPS)
