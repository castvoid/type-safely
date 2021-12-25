
#include "Platform.hpp"

extern "C" {
#include "PlatformTime_c.h"

uint32_t platform_time_millis() {
    return Platform::Time::TimeMillis();
}

uint32_t platform_time_micros() {
    return Platform::Time::TimeMicros();
}
}