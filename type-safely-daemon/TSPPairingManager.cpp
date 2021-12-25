#include <utility>
#include <unistd.h>
#include <fstream>
#include <string>
#include <dirent.h>

#include "TSPPairingManager.hpp"

#define EXTENSION "key"

// https://stackoverflow.com/a/20446239
static bool has_suffix(const std::string &str, const std::string &suffix) {
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static bool isValidID(const std::string &id) {
    for (const char &c : id) {
        if (
            !(c >= '0' && c <= '9') &&
            !(c >= 'A' && c <= 'F')
        ) return false;
    }

    return true;
}

static void validateID(const std::string &id) {
    if (!isValidID(id)) throw std::string("Invalid ID");
}

static std::string getFilePath(const std::string &dir, const std::string &id) {
    validateID(id);

    std::string filePath = dir + id + "." + EXTENSION;
    return filePath;
}

TSPPairingManager::TSPPairingManager(const std::string applicationStoragePath) : applicationStoragePath(applicationStoragePath) {

}

TSPPairingManager::~TSPPairingManager() = default;

std::vector<std::string> TSPPairingManager::getPairedIDs() {
    std::shared_lock lock(mutex_read);

    DIR *dr = opendir(this->applicationStoragePath.c_str());

    if (!dr) {
        perror("Could not open LTK storage directory");
        throw std::string("Could not open LTK storage directory");
    }

    constexpr auto extension_total_len = sizeof(EXTENSION) - 1 + 1; // yep
    std::vector<std::string> id_list{};
    struct dirent *entry;
    while ((entry = readdir(dr))) {
        std::string filename = std::string(entry->d_name);
        if (!has_suffix(filename, "." EXTENSION)) continue;

        std::string basename = filename.substr(0, filename.size() - extension_total_len);
        id_list.push_back(basename);
    }

    closedir(dr);

    return id_list;
}

bool TSPPairingManager::hasPairingForID(const std::string id) {
    std::shared_lock lock(mutex_read);

    std::string filePath = getFilePath(this->applicationStoragePath, id);

    bool file_exists = access(filePath.c_str(), F_OK) != -1;
    return file_exists;
}

std::vector<char> TSPPairingManager::getLTKForID(const std::string id) {
    std::shared_lock lock(mutex_read);

    std::string filePath = getFilePath(this->applicationStoragePath, id);

    std::basic_ifstream<char> inFile(filePath, std::ios::in | std::ios::binary);
    return std::vector<char>(std::istreambuf_iterator<char>{inFile}, {});
}

void TSPPairingManager::storeLTKForID(const std::string id, const std::vector<char> ltk) {
    std::unique_lock lock_r(mutex_read);
    std::unique_lock lock_w(mutex_write);

    std::string filePath = getFilePath(this->applicationStoragePath, id);

    std::basic_ofstream<char> outFile(filePath, std::ios::out | std::ofstream::binary);
    std::copy(ltk.begin(), ltk.end(), std::ostreambuf_iterator<char>(outFile));

    lock_r.unlock();

    if (this->eventCallback_only_call_with_unique_mutex_ownership) {
        this->eventCallback_only_call_with_unique_mutex_ownership(this->eventCallback_userData, PairingEvent::Updated);
    }
}

void TSPPairingManager::eraseLTKForID(const std::string id) {
    std::unique_lock lock_r(mutex_read);
    std::unique_lock lock_w(mutex_write);

    std::string filePath = getFilePath(this->applicationStoragePath, id);

    if (remove(filePath.c_str()) != 0) {
        throw std::string("Failed to remove LTK");
    }

    lock_r.unlock();

    if (this->eventCallback_only_call_with_unique_mutex_ownership) {
        this->eventCallback_only_call_with_unique_mutex_ownership(this->eventCallback_userData, PairingEvent::Removed);
    }
}

void TSPPairingManager::SetEventCallback(TSPPairingManager::EventCallbackType callback, void *userData) {
    std::unique_lock lock(mutex_read);

    this->eventCallback_only_call_with_unique_mutex_ownership = callback;
    this->eventCallback_userData = userData;
}


