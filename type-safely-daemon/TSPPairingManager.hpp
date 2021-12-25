#pragma once

#include <string>
#include <vector>
#include <shared_mutex>

// This class is thread safe.

class TSPPairingManager {
protected:
    std::string applicationStoragePath;

public:
    enum class PairingEvent{
        Updated,
        Removed,
    };

    using EventCallbackType = void (*)(void *userData, PairingEvent event);

    explicit TSPPairingManager(std::string applicationStoragePath);
    ~TSPPairingManager();

    std::vector<std::string> getPairedIDs();
    bool hasPairingForID(std::string id);
    std::vector<char> getLTKForID(std::string id);
    void storeLTKForID(std::string id, std::vector<char> ltk);
    void eraseLTKForID(std::string id);
    void SetEventCallback(EventCallbackType callback, void *userData = nullptr);

protected:
    std::mutex mutex_write;
    std::shared_mutex mutex_read;

    // self documenting code
    EventCallbackType eventCallback_only_call_with_unique_mutex_ownership = nullptr;
    void *eventCallback_userData = nullptr;
};
