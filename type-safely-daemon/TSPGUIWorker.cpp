#include <cinttypes>
#include <unistd.h>
#include "tsp_host_state_machine.hpp"
#include "TSPGUIWorker.hpp"
#include "HIDHandler.hpp"
#include "crypto.h"
#include "usb.h"
#include "utils.h"

std::string fname_for_id(std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id) {
    return Utils::buf_to_hex(id.data(), id.size());
}

TSPGUIWorker::TSPGUIWorker(void *handle, TSPPairingManager &pairingManager) : handle(handle), pairingManager(pairingManager) {

}

TSPGUIWorker::~TSPGUIWorker() {
    delete this->wizard;
}

template <typename E>
static constexpr auto to_underlying(E e) noexcept
{
    return static_cast<std::underlying_type_t<E>>(e);
}

class GUIDelegate : public TypeSafelyProtocol::StateMachine::IDelegate {
private:
    HIDHandler hid_handler;
    TSPGUIWorker *gui_worker;
    TSPPairingManager &pairingManager;

public:
    explicit GUIDelegate(TSPGUIWorker *gw, TSPPairingManager &pm) : gui_worker(gw), pairingManager(pm), hid_handler() {
        hid_handler.Setup();
    }

    bool get_random_bytes(uint8_t *buf, size_t len) override {
        return Crypto::generate_random_bytes(buf, len);
    }

    bool does_recognise_id(std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id) override {
        std::string fname = fname_for_id(id);

        return this->pairingManager.hasPairingForID(fname);
    }

    bool ltk_for_id(std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id, std::array<uint8_t, TypeSafelyProtocol::len_ltk> &ltk) override {
        std::string fname = fname_for_id(id);

        std::vector<char> ltk_vec;
        try {
            ltk_vec = this->pairingManager.getLTKForID(fname);
        } catch (...) {
            fprintf(stderr, "Failed to fetch ltk for ID %s\n", fname.c_str());
            return false;
        }

        if (ltk_vec.size() != TypeSafelyProtocol::len_ltk) {
            fprintf(stderr, "Unexpectedly read %zu bytes for ID %s's LTK, rather than %zu.\n", ltk_vec.size(), fname.c_str(), TypeSafelyProtocol::len_ltk);
            return false;
        }

        std::copy_n(ltk_vec.begin(), ltk.size(), ltk.begin());
        return true;
    }

    bool store_ltk_for_id(std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id, std::array<uint8_t, TypeSafelyProtocol::len_ltk> &ltk) override {
        std::string fname = fname_for_id(id);

        try {
            this->pairingManager.storeLTKForID(fname, std::vector<char>(ltk.begin(), ltk.end()));
        } catch (...) {
            fprintf(stderr, "Failed to store ltk for ID %s\n", fname.c_str());
            return false;
        }

        return true;
    }

    bool erase_ltk_for_id(std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id) override {
        std::string fname = fname_for_id(id);

        try {
            this->pairingManager.eraseLTKForID(fname);
        } catch (...) {
            fprintf(stderr, "Failed to erase ltk for ID %s\n", fname.c_str());
            return false;
        }

        return true;
    }

    bool crypto_generate_ecdh_keypair(std::array<uint8_t, TypeSafelyProtocol::len_private_key> &key_private, std::array<uint8_t, TypeSafelyProtocol::len_public_key> &key_public) override {
        return Crypto::generate_keypair(key_private, key_public);
    }

    bool crypto_derive_dhkey(const std::array<uint8_t, TypeSafelyProtocol::len_private_key> &key_private,
                             const std::array<uint8_t, TypeSafelyProtocol::len_public_key> &key_public,
                             std::array<uint8_t, TypeSafelyProtocol::len_dh_key> &dhkey) override {
        return Crypto::derive_dhkey(key_private, key_public, dhkey);
    }

    bool crypto_aes_128_cmac(const std::array<uint8_t, 16> &key,
                             const uint8_t *msg,
                             size_t msg_len,
                             std::array<uint8_t, 16> &mac) override {
        return Crypto::compute_aes_128_cmac(key, msg, msg_len, mac);
    }

    bool crypto_aes_ccm_decrypt(
        const std::array<uint8_t, 16> &key,
        const std::array<uint8_t, 13> &nonce,
        const uint8_t *cipher_msg,
        size_t msg_len,
        uint8_t *plaintext,
        const std::array<uint8_t, 16> &tag) override {
        return Crypto::decrypt_aes_ccm(key, nonce, cipher_msg, msg_len, plaintext, tag);
    }

    bool generate_display_passkey(std::array<uint8_t, 16> &passkey_arr) override {
        uint32_t pass_num;

        // Generate passkeys until we find one where the int formed by the lower 20 bits is only 6 digits
        do {
            const bool ok = Crypto::generate_random_bytes(reinterpret_cast<uint8_t *>(&pass_num), sizeof(pass_num));
            if (!ok) return false;
        } while ((pass_num &= ((1 << 21) - 1)) >= 1e6);

        passkey_arr = {0};
        size_t num_bytes_in_pass_num = sizeof(pass_num);
        assert(num_bytes_in_pass_num < passkey_arr.size());
        for (size_t i = 0; i < num_bytes_in_pass_num; i++) {
            passkey_arr[i] = static_cast<uint8_t>((pass_num >> (i * 8)) & 0xFF);
        }

        emit gui_worker->displayPin(pass_num);

        return true;
    }

    void dismiss_passkey_display() override {
        emit gui_worker->pinEntryComplete();
    }

    void tsp_sm_received_error(const char *type) override {
        printf("Received error: %s\n", type);
    }

    void tsp_sm_encountered_error(const char *type) override {
        printf("Encountered error: %s\n", type);
    }

    void tsp_recieved_new_packet(std::array<uint8_t, 8> &packet) override {
//        char str[64] = {0};
        // snprintf(str, sizeof(str), "%02x %02x %02x %02x %02x %02x %02x %02x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5], packet[6], packet[7]);\

        hid_handler.HandleHIDData(packet);
    }

    void encrypted_session_began() override {
        emit gui_worker->pairingSucceeded();
    }

    bool ready_to_begin_pairing() override {
        return gui_worker->readyToPair();
    }
};

static void sec_tick(TypeSafelyProtocol::HostStateMachine &host, void *handle, uint8_t *in_buf, size_t in_len) {
    static uint8_t out_buf[64] = {0};
    auto state_old = host.getState();

    auto used = ((TypeSafelyProtocol::StateMachine &)host).tick(in_buf, in_len, out_buf, sizeof(out_buf));
    auto state_new = host.getState();
    if (state_new != state_old) printf("HOST: %d -> %d\n", to_underlying(state_old), to_underlying(state_new));
    if (used < 0) {
        assert(false);
    } else if (used > 0) {
        if (used > UINT16_MAX) return;
        usb_write(handle, out_buf, used);
    }
}

void TSPGUIWorker::process() {
    printf("Worker beginning processing...\n");
    GUIDelegate delegate(this, this->pairingManager);
    std::array<uint8_t, TypeSafelyProtocol::len_entity_id> id_host = {1};
    auto host = TypeSafelyProtocol::HostStateMachine(delegate, id_host);
    uint8_t buffer_in[128];

    while (!should_exit) {
        auto len_read = usb_read(handle, buffer_in, sizeof(buffer_in));
        if (len_read > 0) {
            sec_tick(host, handle, buffer_in, static_cast<size_t>(len_read));
        } else {
            sec_tick(host, handle, nullptr, 0);
        }
    }

    printf("Worker deleting self\n");
    delete this;
}

void TSPGUIWorker::beginPairing(TSPPairingWizard *wizard) {
    this->wizard = wizard;
    this->pairing_ok = true;
}

TSPPairingWizard *TSPGUIWorker::getWizard() {
    return this->wizard;
}

bool TSPGUIWorker::readyToPair() {
    if (first) {
        emit pairingAvailable();
        first = false;
    }

    return this->pairing_ok;
}

void TSPGUIWorker::exit() {
    this->should_exit = true;
}