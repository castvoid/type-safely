ifeq ($(BOARD), 1BITSY)
CPPFLAGS += -DSTM32F4 -DSTM32F4_1BITSY -DF_CPU=168000000 -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16
LDFLAGS += -T$(PLATFORM_DIR)/stm32f415.ld -lopencm3_stm32f4 -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16
else
ifneq ($(MAKECMDGOALS), clean)
$(error Unknown board)
endif
endif