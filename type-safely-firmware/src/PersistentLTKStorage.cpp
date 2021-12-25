#include <Platform.hpp>
#include <cstring>
#include <assert.h>
#include "PersistentLTKStorage.hpp"

#define EEPROM_ADDR 0
#define LEN_ID 7
#define LEN_LTK 16
#define LEN_CACHE 3
#define LEN_CRC 4

static const uint8_t kMagic[2] = {0xDA, 0xB5};
static const uint8_t kVersion = 2;

static constexpr size_t len_LTKEntry = 1 + LEN_ID + LEN_LTK;
static constexpr size_t len_header = sizeof(kMagic) + sizeof(kVersion);
static constexpr size_t len_data = len_header + LEN_ID + (LEN_CACHE * len_LTKEntry);

typedef struct {
    uint8_t valid;
    std::array<uint8_t, LEN_ID> id;
    std::array<uint8_t, LEN_LTK> ltk;
} LTKEntry;


// ========================================
// Implementation
static std::array<LTKEntry, LEN_CACHE> ltk_cache{};
static std::array<uint8_t, LEN_ID> own_id{};

static void unpack_ltkentry(const uint8_t *buf, LTKEntry &entry) {
    entry.valid = buf[0];
    memcpy(entry.id.data(), buf + 1, LEN_ID);
    memcpy(entry.ltk.data(), buf + 1 + LEN_ID, LEN_LTK);
    static_assert(1 + LEN_ID + LEN_LTK == len_LTKEntry);
}

static void pack_ltkentry(uint8_t *buf, const LTKEntry &entry) {
    buf[0] = entry.valid;
    memcpy(buf + 1, entry.id.data(), LEN_ID);
    memcpy(buf + 1 + LEN_ID, entry.ltk.data(), LEN_LTK);
    static_assert(1 + LEN_ID + LEN_LTK == len_LTKEntry);
}

static bool ps_load() {
    std::array<uint8_t, len_data + LEN_CRC> record{0};
    bool read_ok = Platform::EEPROM::Read(EEPROM_ADDR, record.data(), record.size());
    if (!read_ok) return false;

    if (record[0] != kMagic[0] || record[1] != kMagic[1]) {
        // wasn't our data
        return false;
    }

    if (record[2] != kVersion) return false;

    // Check CRC
    uint32_t crc_stored = 0;
    static_assert(record.size() >= LEN_CRC);
    static_assert(LEN_CRC == sizeof(crc_stored));
    memcpy(&crc_stored, record.data() + record.size() - LEN_CRC, LEN_CRC);
    const uint32_t crc_calculated = Platform::Utils::CRC32(record.data(), record.size() - LEN_CRC);
    if (crc_calculated != crc_stored) return false;

    // Get own ID
    {
        static_assert(own_id.size() == LEN_ID);
        const uint8_t *base = record.data() + len_header;
        memcpy(own_id.data(), base, LEN_ID);
    }

    // Copy out entries
    for (size_t i = 0; i < ltk_cache.size(); i++) {
        const uint8_t *base = record.data() + len_header + LEN_ID + (len_LTKEntry * i);
        unpack_ltkentry(base, ltk_cache[i]);
    }

    return true;
}

static bool ps_store() {
    std::array<uint8_t, len_data + LEN_CRC> record{0};

    // Header
    record[0] = kMagic[0];
    record[1] = kMagic[1];
    record[2] = kVersion;

    // Copy own ID
    {
        static_assert(own_id.size() == LEN_ID);
        uint8_t *base = record.data() + len_header;
        memcpy(base, own_id.data(), LEN_ID);
    }

    // Copy out entries
    for (size_t i = 0; i < ltk_cache.size(); i++) {
        uint8_t *base = record.data() + len_header + LEN_ID + (len_LTKEntry * i);
        pack_ltkentry(base, ltk_cache[i]);
    }

    // CRC
    const uint32_t crc_calculated = Platform::Utils::CRC32(record.data(), record.size() - LEN_CRC);
    memcpy(record.data() + record.size() - LEN_CRC, &crc_calculated, LEN_CRC);

    // Write to EEPROM
    return Platform::EEPROM::Write(EEPROM_ADDR, record.data(), record.size());
}

bool PersistentLTKStorage::Setup() {
    if (!ps_load()) {
        return Reset();
    }

    return true;
}

bool PersistentLTKStorage::GetOwnID(std::array<uint8_t, LEN_ID> &id) {
    id = own_id;

    return true;
}

bool PersistentLTKStorage::HaveLTKForEntityID(std::array<uint8_t, LEN_ID> &id) {
    for (LTKEntry &entry : ltk_cache) {
        if (entry.valid == 1 && entry.id == id) return true;
    }

    return false;
}

bool PersistentLTKStorage::GetLTKForEntityID(const std::array<uint8_t, LEN_ID> &id, std::array<uint8_t, LEN_LTK> &ltk) {
    for (LTKEntry &entry : ltk_cache) {
        if (entry.valid != 1 || entry.id != id) continue;

        ltk = entry.ltk;
        return true;
    }

    return false;
}

bool PersistentLTKStorage::SetLTKForEntityID(const std::array<uint8_t, LEN_ID> &id, const std::array<uint8_t, LEN_LTK> &ltk) {
    LTKEntry *entry_for_ltk = nullptr;
    for (LTKEntry &entry : ltk_cache) {
        if (entry.valid || entry.id != id) continue;

        entry_for_ltk = &entry;
        break;
    }
    if (entry_for_ltk == nullptr) entry_for_ltk = &ltk_cache.back();

    entry_for_ltk->valid = 1;
    entry_for_ltk->id = id;
    entry_for_ltk->ltk = ltk;

    return ps_store();
}

bool PersistentLTKStorage::ClearLTKForEntityID(std::array<uint8_t, LEN_ID> &id) {
    for (LTKEntry &entry : ltk_cache) {
        if (!entry.valid || entry.id != id) continue;
        entry = {0};
    }

    return ps_store();
}


bool PersistentLTKStorage::ClearAllPairings() {
    for (LTKEntry &entry : ltk_cache) {
        entry = {0};
    }

    return ps_store();
}

bool PersistentLTKStorage::Reset() {
    // Reset ID
    Platform::Crypto::GetRandomBytes(own_id.data(), own_id.size());

    // Clear pairings
    for (LTKEntry &entry : ltk_cache) {
        entry = {0};
    }

    // Store
    return ps_store();
}