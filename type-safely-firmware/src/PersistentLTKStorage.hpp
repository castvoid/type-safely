#pragma once

#include <cstdint>
#include <array>

namespace PersistentLTKStorage {
    bool Setup();

    bool GetOwnID(std::array<uint8_t, 7> &id);
    bool HaveLTKForEntityID(std::array<uint8_t, 7> &id);
    bool GetLTKForEntityID(const std::array<uint8_t, 7> &id, std::array<uint8_t, 16> &ltk);
    bool SetLTKForEntityID(const std::array<uint8_t, 7> &id, const std::array<uint8_t, 16> &ltk);
    bool ClearLTKForEntityID(std::array<uint8_t, 7> &id);
    bool ClearAllPairings();
    bool Reset();
};
