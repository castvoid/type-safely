#include <stdint.h>

#include "Platform.hpp"
#include <libopencm3/cm3/dwt.h>
#include <libopencm3/cm3/nvic.h>
#include <libopencm3/cm3/systick.h>
#include <libopencm3/stm32/rcc.h>

static volatile uint32_t millis_count;

#ifdef STM32F4_1BITSY
// See rationale for these constants in Platform::Time::Setup
static const uint_fast16_t kTicksPerMilli = 168000; // Set to interrupt every 9000 ticks = 1000 times per sec
static const uint_fast8_t  kTicksPerMicro = kTicksPerMilli / 1000;
#endif


void Platform::Time::Setup() {
    millis_count = 0;
    dwt_enable_cycle_counter();

    // Set the systick timer to interrupt every millisecond
#ifdef STM32F4_1BITSY
    rcc_clock_setup_hse_3v3(&rcc_hse_25mhz_3v3[RCC_CLOCK_3V3_168MHZ]); // 168MHz
    rcc_periph_clock_enable(RCC_GPIOD);

    systick_set_clocksource(STK_CSR_CLKSOURCE_AHB);
    systick_set_reload(kTicksPerMilli - 1); // restart counter (counting down)
    systick_counter_enable();
    systick_interrupt_enable(); // interrupts when counter reaches 0
#else
#warning Unknown board — couldnt set up clock.
#endif
}



/**
  Declared in libopencm3/cm3/nvic.h. Called every time our systick timer reaches
  0, which is set to be every ms.
 */
void sys_tick_handler(void) {
    millis_count++;
}


/**
 Uses simple cycle counting, but using DWT_CYCCNT rather than assuming cycles
 per instruction (which I found to be less than predictable between different
 ARMs).

 Optimise for size to try to decrease the # cycles spent _in_ the loop, giving
 more accurate timing.
 */
__attribute__((optimize("Os"))) void Platform::Time::DelayMicros(uint32_t usec) {
    uint32_t initial = DWT_CYCCNT;

    uint64_t cycles = usec * (F_CPU / 1000000);
    if (cycles > UINT32_MAX) cycles = UINT32_MAX;

    while (DWT_CYCCNT - initial < cycles) {}
}


void Platform::Time::DelayMillis(uint32_t msec) {
    auto extraTicks = systick_get_value();
    auto startMS = Platform::Time::TimeMillis();

    while (Platform::Time::TimeMillis() - startMS < msec) {
        // XXX: This line is commented out because sleep modes break
        // Segger RTT...

        // __asm__("wfi");
    }

    while (systick_get_reload() - systick_get_value() < extraTicks) {
        // do nothing
    }
}


uint32_t Platform::Time::TimeMillis() {
    uint32_t count;

    auto initial = Platform::Atomic::EnterCritical();
    count = millis_count;
    Platform::Atomic::ExitCritical(initial);

    return count;
}


uint32_t Platform::Time::TimeMicros(){
    auto initial = Platform::Atomic::EnterCritical();
    uint32_t t = millis_count * 1000;
    t += ((kTicksPerMilli-systick_get_value()) / kTicksPerMicro) % 1000;
    Platform::Atomic::ExitCritical(initial);

    return t;
}
