#pragma once

#include <cstdint>
#include <array>


class HIDLockdownManager {
public:
    enum class LockdownLevel {
        Unknown,
        AllowAll,
        DisableUntrustedKeyboards,
    };
    explicit HIDLockdownManager();
    ~HIDLockdownManager();

    bool Setup();
    bool SetLockdownLevel(LockdownLevel level);
    LockdownLevel GetLockdownLevel();

protected:
    LockdownLevel lastSetLockdownLevel;
};
