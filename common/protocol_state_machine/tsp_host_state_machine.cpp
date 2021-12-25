#include "tsp_host_state_machine.hpp"
#include <cassert>
#include <vector>
#include <string>
#include <memory>
#include <messages.pb.h>
#include <chrono>
#include "tsp_implementation_helpers.hpp"
#include "messages.pb.h"

#define STATE_ARGS const typesafely_protocol_MessageWrapper *in_msg_wrapper, typesafely_protocol_MessageWrapper &out_wrapper, StateMachine::StateMachineMemory &memory, StateMachine::IDelegate &delegate, HostStateMachine::State &state, std::chrono::time_point<std::chrono::system_clock> &timer
#define STATE_ARG_NAMES in_msg_wrapper, out_wrapper, memory, delegate, state, timer

#define TIMEOUT_INITIALMSG 250L
#define TIMEOUT_DEFAULT 1000L

static void hst_timer_reset(std::chrono::time_point<std::chrono::system_clock> &timer) {
    timer = std::chrono::system_clock::now();
}

static bool hst_timer_expired(std::chrono::time_point<std::chrono::system_clock> &timer, long timeout_ms) {
    auto time_now = std::chrono::system_clock::now();
    auto ms_passed = std::chrono::duration_cast<std::chrono::milliseconds>(time_now - timer).count();

    return ms_passed >= timeout_ms;
}

#define TIMER_RESET() hst_timer_reset(timer)
#define VALIDATE_TIMER(timeout_ms) \
do { \
    bool expired = hst_timer_expired(timer, timeout_ms); \
    if (expired) { \
        state = HostStateMachine::State::Initial;\
        printf("(timeout after %lums)\n", timeout_ms);\
        return false;\
    }\
} while (0)
#define EXPECT_IN_MSG_TIMEOUT(timeout_ms) \
do { \
    if (in_msg_wrapper == nullptr) VALIDATE_TIMER(timeout_ms); \
} while (0)

namespace TypeSafelyProtocol {
    using TransitionFnPtr = bool (*)(STATE_ARGS);

    static bool message_has_type(const typesafely_protocol_MessageWrapper *in_msg_wrapper, pb_size_t expected_type) {
        if (in_msg_wrapper == nullptr) return false;
        return in_msg_wrapper->which_message == expected_type;
    }

    static bool report_error(const char *type, STATE_ARGS, typesafely_protocol_Error_RecoveryAction recovery_action = typesafely_protocol_Error_RecoveryAction_RESET_CONNECTION) {
        delegate.tsp_sm_encountered_error(type);

        assert(strlen(type) < 63);
        typesafely_protocol_Error out_msg = typesafely_protocol_Error_init_zero;
        strncpy(out_msg.error_type, type, sizeof(out_msg.error_type));
        out_msg.recovery_action = recovery_action;

        out_wrapper.which_message = MessageTypeError;
        out_wrapper.message.message_typesafely_protocol_Error = out_msg;

        switch (recovery_action) {
            case typesafely_protocol_Error_RecoveryAction_IGNORE:
                break;
            case typesafely_protocol_Error_RecoveryAction_RESTART_PAIRING:
                state = HostStateMachine::State::InitiatePairing;
                break;
            case typesafely_protocol_Error_RecoveryAction_RESET_CONNECTION:
            default:
                state = HostStateMachine::State::Initial;
                break;
        }

        return true;
    }

    static bool handle_unexpected_message(STATE_ARGS) {
        if (message_has_type(in_msg_wrapper, MessageTypeError)) {
            auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_Error;
            delegate.tsp_sm_received_error(in_msg.error_type);

            switch (in_msg.recovery_action) {
                case typesafely_protocol_Error_RecoveryAction_IGNORE:
                    return false;
                case typesafely_protocol_Error_RecoveryAction_RESTART_PAIRING:
                    state = HostStateMachine::State::InitiatePairing;
                    return false;
                case typesafely_protocol_Error_RecoveryAction_RESET_CONNECTION:
                default:
                    state = HostStateMachine::State::Initial;
                    return false;
            }
            return false;
        } else {
            fprintf(stderr, "Message type: %zu\n", static_cast<size_t>(in_msg_wrapper->which_message));
            return report_error("UNKNOWN_MESSAGE", STATE_ARG_NAMES, typesafely_protocol_Error_RecoveryAction_RESET_CONNECTION);
        }

        return false;
    }

    // ==============================
    // State machine states
    static bool host_state_initial(STATE_ARGS) {
        // Check there's no message
        if (in_msg_wrapper != nullptr) return handle_unexpected_message(STATE_ARG_NAMES);

        // Create an init message
        typesafely_protocol_connection_ConnectRequest out_msg = {};
        if (!COPY_ARR_TO_BUF(memory.connection.id_host, out_msg.id_host)) return report_error("INCORRECT_SIZE", STATE_ARG_NAMES);

        // Wrap the output
        out_wrapper.which_message = MessageTypeConnectionConnectRequest;
        out_wrapper.message.message_typesafely_protocol_connection_ConnectRequest = out_msg;
        state = HostStateMachine::State::ConnectRequestSent;
        return true;
    }


    static bool host_state_connect_request_sent(STATE_ARGS) {
        EXPECT_IN_MSG_TIMEOUT(TIMEOUT_INITIALMSG);
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypeConnectionConnectResponse);

        auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_connection_ConnectResponse;
        if (!COPY_BUF_TO_ARR(in_msg.id_device, memory.connection.id_device)) return report_error("INCORRECT_SIZE", STATE_ARG_NAMES);
        memory.connection.device_recognises_host_id = in_msg.device_recognises_host_id;

        memory.connection.host_recognises_device_id = delegate.does_recognise_id(memory.connection.id_device);

        if (memory.connection.host_recognises_device_id && memory.connection.device_recognises_host_id) {
            state = HostStateMachine::State::OpenSession;
        } else {
            state = HostStateMachine::State::InitiatePairing;
        }

        return false;
    }


    static bool host_state_initiate_pairing(STATE_ARGS) {
        if (in_msg_wrapper != nullptr) return handle_unexpected_message(STATE_ARG_NAMES);

        if (!delegate.ready_to_begin_pairing()) return false;

        delegate.crypto_generate_ecdh_keypair(memory.pairing.keys.private_host, memory.pairing.keys.public_host);

        typesafely_protocol_pairing_InitiatePairingRequest out_msg = {};
        out_msg.host_recognises_device_id = memory.connection.host_recognises_device_id;
        if (!COPY_ARR_TO_BUF(memory.pairing.keys.public_host, out_msg.host_ecdh_public_key.public_key)) return report_error("INTERNAL", STATE_ARG_NAMES);

        out_wrapper.which_message = MessageTypePairingInitiatePairingRequest;
        out_wrapper.message.message_typesafely_protocol_pairing_InitiatePairingRequest = out_msg;
        state = HostStateMachine::State::InitiatePairingRequestSent;

        return true;
    }


    static bool host_state_initiate_pairing_request_sent(STATE_ARGS) {
        EXPECT_IN_MSG_TIMEOUT(TIMEOUT_DEFAULT);
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypePairingInitiatePairingResponse);

        auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_pairing_InitiatePairingResponse;
        if (!COPY_BUF_TO_ARR(in_msg.device_ecdh_public_key.public_key, memory.pairing.keys.public_device)) return report_error("INCORRECT_SIZE", STATE_ARG_NAMES);

        // derive dhkey
        if (!delegate.crypto_derive_dhkey(
            memory.pairing.keys.private_host,
            memory.pairing.keys.public_device
            , memory.pairing.dh_key)
            ) return report_error("INTERNAL", STATE_ARG_NAMES);

        if (!delegate.generate_display_passkey(memory.pairing.passkey_host)) return report_error("INTERNAL", STATE_ARG_NAMES);

        typesafely_protocol_pairing_BeginAuthenticationRequest out_msg = {};
        out_wrapper.which_message = MessageTypePairingBeginAuthenticationRequest;
        out_wrapper.message.message_typesafely_protocol_pairing_BeginAuthenticationRequest = out_msg;
        state = HostStateMachine::State::BeginAuthenticationRequestSent;
        return true;
    }


    static bool host_state_begin_authentication_request_sent(STATE_ARGS) {
        // TODO: add message type saying "yeah I'm still taking input and here" then add timeout
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypePairingBeginAuthenticationResponse);
        delegate.dismiss_passkey_display();


        // Generate host nonce
        if (!delegate.get_random_bytes(memory.pairing.nonce_host.data(), memory.pairing.nonce_host.size())) return report_error("INTERNAL", STATE_ARG_NAMES);

        // Calculate commitment
        std::array<uint8_t, 32> pubkey_x_host{}, pubkey_x_device{};
        crypto_ec_pubkey_get_x(memory.pairing.keys.public_host, pubkey_x_host);
        crypto_ec_pubkey_get_x(memory.pairing.keys.public_device, pubkey_x_device);

        bool commitment_calc_succeeded = crypto_ble_f4(
            delegate,
            pubkey_x_host,
            pubkey_x_device,
            memory.pairing.nonce_host,
            memory.pairing.passkey_host,
            memory.pairing.commitment_host
            );

        if (!commitment_calc_succeeded) return report_error("INTERNAL", STATE_ARG_NAMES);

        typesafely_protocol_pairing_CommitmentExchangeRequest out_msg = {};
        COPY_ARR_TO_BUF(memory.pairing.commitment_host, out_msg.host_commitment);

        out_wrapper.which_message = MessageTypePairingCommitmentExchangeRequest;
        out_wrapper.message.message_typesafely_protocol_pairing_CommitmentExchangeRequest = out_msg;
        state = HostStateMachine::State::CommitmentExchangeRequestSent;
        return true;
    }


    static bool host_state_commitment_exchange_request_sent(STATE_ARGS) {
        EXPECT_IN_MSG_TIMEOUT(TIMEOUT_DEFAULT);
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypePairingCommitmentExchangeResponse);

        auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_pairing_CommitmentExchangeResponse;
        COPY_BUF_TO_ARR(in_msg.device_commitment, memory.pairing.commitment_device);

        typesafely_protocol_pairing_NonceExchangeRequest out_msg = {};
        COPY_ARR_TO_BUF(memory.pairing.nonce_host, out_msg.host_nonce);

        out_wrapper.which_message = MessageTypePairingNonceExchangeRequest;
        out_wrapper.message.message_typesafely_protocol_pairing_NonceExchangeRequest = out_msg;
        state = HostStateMachine::State::NonceExchangeRequestSent;
        return true;
    }


    static bool host_state_nonce_exchange_request_sent(STATE_ARGS) {
        EXPECT_IN_MSG_TIMEOUT(TIMEOUT_DEFAULT);
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypePairingNonceExchangeResponse);

        auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_pairing_NonceExchangeResponse;
        COPY_BUF_TO_ARR(in_msg.device_nonce, memory.pairing.nonce_device);

        std::array<uint8_t, 32> pubkey_x_host{}, pubkey_x_device{};
        crypto_ec_pubkey_get_x(memory.pairing.keys.public_host, pubkey_x_host);
        crypto_ec_pubkey_get_x(memory.pairing.keys.public_device, pubkey_x_device);

        std::array<uint8_t, len_commitment> recalculated_device_commitment{};
        bool commitment_recalc_succeeded = crypto_ble_f4(
            delegate,
            pubkey_x_device,
            pubkey_x_host,
            memory.pairing.nonce_device,
            memory.pairing.passkey_host,
            recalculated_device_commitment
        );
        if (!commitment_recalc_succeeded) return report_error("INTERNAL", STATE_ARG_NAMES);

        bool recomputed_commitment_matches = (recalculated_device_commitment == memory.pairing.commitment_device);

        if (!recomputed_commitment_matches) {
            fprintf(stderr, "Device sent invalid commitment!\n");
            return report_error("INVALID_COMMITMENT", STATE_ARG_NAMES, typesafely_protocol_Error_RecoveryAction_RESTART_PAIRING);
        } else {
            bool calculated_f5 = crypto_ble_f5(
                delegate,
                memory.pairing.dh_key,
                memory.pairing.nonce_host,
                memory.pairing.nonce_device,
                memory.connection.id_host,
                memory.connection.id_device,
                memory.pairing.mac_key,
                memory.pairing.ltk
                );

            if (!calculated_f5) return report_error("INTERNAL", STATE_ARG_NAMES);

            std::array<uint8_t, 16> confirmation{};

            bool calculated_f6 = crypto_ble_f6(
                delegate,
                memory.pairing.mac_key,
                memory.pairing.nonce_host,
                memory.pairing.nonce_device,
                memory.pairing.passkey_host,
                {static_cast<uint8_t>(memory.connection.host_recognises_device_id)},
                memory.connection.id_host,
                memory.connection.id_device,
                confirmation
                );
            if (!calculated_f6) return report_error("INTERNAL", STATE_ARG_NAMES);

            typesafely_protocol_pairing_ParameterConfirmationRequest out_msg = {};
            if (!COPY_ARR_TO_BUF(confirmation, out_msg.host_parameter_confirmation)) return report_error("INTERNAL", STATE_ARG_NAMES);

                out_wrapper.which_message = MessageTypePairingParameterConfirmationRequest;
            out_wrapper.message.message_typesafely_protocol_pairing_ParameterConfirmationRequest = out_msg;
            state = HostStateMachine::State::ParameterConfirmationRequestSent;
            return true;
        }
    }


    static bool host_state_parameter_confirmation_request_sent(STATE_ARGS) {
        EXPECT_IN_MSG_TIMEOUT(TIMEOUT_DEFAULT);
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypePairingParameterConfirmationResponse);

        auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_pairing_ParameterConfirmationResponse;
        std::array<uint8_t, 16> device_confirmation_recieved{};
        if (!COPY_BUF_TO_ARR(in_msg.device_parameter_confirm, device_confirmation_recieved)) return report_error("INTERNAL", STATE_ARG_NAMES);

        // Recompute device's confirmation
        std::array<uint8_t, 16> device_confirmation_recomputed{};

        bool calculated_f6 = crypto_ble_f6(
            delegate,
            memory.pairing.mac_key,
            memory.pairing.nonce_device,
            memory.pairing.nonce_host,
            memory.pairing.passkey_host,
            {static_cast<uint8_t>(memory.connection.device_recognises_host_id)},
            memory.connection.id_device,
            memory.connection.id_host,
            device_confirmation_recomputed
        );
        if (!calculated_f6) return report_error("INTERNAL", STATE_ARG_NAMES);

        if (device_confirmation_recieved != device_confirmation_recomputed) {
            fprintf(stderr, "Device sent invalid confirmation!\n");
            return report_error("INVALID_CONFIRMATION", STATE_ARG_NAMES, typesafely_protocol_Error_RecoveryAction_RESTART_PAIRING);
        } else {
            if (!delegate.store_ltk_for_id(memory.connection.id_device, memory.pairing.ltk)) {
                fprintf(stderr, "Saving LTK failed, restarting pairing...\n");
                return report_error("INTERNAL", STATE_ARG_NAMES, typesafely_protocol_Error_RecoveryAction_RESTART_PAIRING);
            }
            state = HostStateMachine::State::OpenSession;
            return false;
        }
    }


    static bool host_state_open_session(STATE_ARGS) {
        if (in_msg_wrapper != nullptr) return handle_unexpected_message(STATE_ARG_NAMES);

        // Genereate a new key set
        if (!delegate.crypto_generate_ecdh_keypair(memory.session.keys.private_host, memory.session.keys.public_host)) report_error("INTERNAL", STATE_ARG_NAMES);

        // Grab LTK
        std::array<uint8_t, len_ltk> ltk{};
        if (!delegate.ltk_for_id(memory.connection.id_device, ltk)) report_error("UNKOWN_ENTITY_ID", STATE_ARG_NAMES);

        std::array<uint8_t, 16> auth_data{};
        bool could_compute_auth = crypto_gen_session_auth(
            delegate,
            ltk,
            {'H', 'O', 'S', 'T'}, // TODO: non-ascii!
            memory.connection.id_host,
            memory.connection.id_device,
            memory.session.keys.public_host,
            auth_data
            );
        if (!could_compute_auth) report_error("INTERNAL", STATE_ARG_NAMES);

        typesafely_protocol_session_OpenSessionRequest out_msg = {};
        if (!COPY_ARR_TO_BUF(memory.session.keys.public_host, out_msg.host_ecdh_public_key.public_key)) report_error("INTERNAL", STATE_ARG_NAMES);
        if (!COPY_ARR_TO_BUF(auth_data, out_msg.host_authentication_data)) report_error("INTERNAL", STATE_ARG_NAMES);

        out_wrapper.which_message = MessageTypeSessionOpenSessionRequest;
        out_wrapper.message.message_typesafely_protocol_session_OpenSessionRequest = out_msg;
        state = HostStateMachine::State::OpenSessionRequestSent;
        return true;
    }


    static bool host_state_open_session_request_sent(STATE_ARGS) {
        EXPECT_IN_MSG_TIMEOUT(TIMEOUT_DEFAULT);

        if (in_msg_wrapper != nullptr && message_has_type(in_msg_wrapper, MessageTypeError)) {
            auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_Error;

            if (strcmp(in_msg.error_type, "INVALID_AUTH") == 0) {
                printf("Device reports we sent invalid LTK - re-initiating pairing... \n"
                       "(user should probably have some explanation of why this is happening?\n");
                state = HostStateMachine::State::InitiatePairing;
                return false;
            }
        }

        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypeSessionOpenSessionResponse);

        auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_session_OpenSessionResponse;
        if (!COPY_BUF_TO_ARR(in_msg.device_ecdh_public_key.public_key, memory.session.keys.public_device)) report_error("INCORRECT_SIZE", STATE_ARG_NAMES);
        std::array<uint8_t, 16> device_auth{};
        if (!COPY_BUF_TO_ARR(in_msg.device_authentication_data, device_auth)) report_error("INCORRECT_SIZE", STATE_ARG_NAMES);

        // TODO keep in memory?
        std::array<uint8_t, len_ltk> ltk{};
        if (!delegate.ltk_for_id(memory.connection.id_device, ltk)) report_error("UNKOWN_ENTITY_ID", STATE_ARG_NAMES);

        std::array<uint8_t, 16> recomputed_device_auth{};
        bool could_compute_auth = crypto_gen_session_auth(
            delegate,
            ltk,
            {'K', 'E', 'Y', 'B'}, // TODO: non-ascii!
            memory.connection.id_device,
            memory.connection.id_host,
            memory.session.keys.public_device,
            recomputed_device_auth
        );
        if (!could_compute_auth) report_error("INTERNAL", STATE_ARG_NAMES);

        if (recomputed_device_auth != device_auth) {
            fprintf(stderr, "Device sent invalid authentication data!\n");
            return report_error("INVALID_AUTH", STATE_ARG_NAMES);
        } else {
            std::array<uint8_t, 32> dhkey{};
            if (!delegate.crypto_derive_dhkey(memory.session.keys.private_host, memory.session.keys.public_device, dhkey)) return report_error("INTERNAL", STATE_ARG_NAMES);

            if (!crypto_generate_session_key(
                delegate,
                memory.session.keys.private_host,
                memory.session.keys.public_device,
                memory.session_key,
                memory.session_iv
                )) return report_error("INTERNAL", STATE_ARG_NAMES);

            out_wrapper.which_message = MessageTypeSessionUpgradeRequest;
            out_wrapper.message.message_typesafely_protocol_session_UpgradeRequest = {};
            state = HostStateMachine::State::SessionUpgradeRequestSent;
            return true;
        }
    }


    static bool host_state_session_upgrade_request_sent(STATE_ARGS) {
        EXPECT_IN_MSG_TIMEOUT(TIMEOUT_DEFAULT);
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypeSessionUpgradeResponse);

        memory.session_seq_num = 0;

        state = HostStateMachine::State::SessionOpen;
        return false;
    }


    static bool host_state_session_open(STATE_ARGS) {
        // TODO: timeout here, once we can expect messages regularly
        VALIDATE_TIMER(2000L);
        if (message_has_type(in_msg_wrapper, MessageTypeSessionUpgradeResponse)) return false;
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypeSessionPacket);

        auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_session_Packet;
        if (in_msg.sequence_num <= memory.session_seq_num && memory.session_seq_num != 0) {
            if (in_msg.sequence_num == memory.session_seq_num) {
                // just a repeat - ignore
                //printf("r");
                return false;
            }
            return report_error("REPLAY", STATE_ARG_NAMES, typesafely_protocol_Error_RecoveryAction_IGNORE);
        }
        memory.session_seq_num = in_msg.sequence_num;

        std::array<uint8_t, 16> tag{};
        std::array<uint8_t, 8> ciphertext{};
        if (!COPY_BUF_TO_ARR(in_msg.tag, tag)) report_error("INCORRECT_SIZE", STATE_ARG_NAMES);
        if (!COPY_BUF_TO_ARR(in_msg.ciphertext, ciphertext)) report_error("INCORRECT_SIZE", STATE_ARG_NAMES);

        std::array<uint8_t, 13> nonce{};
        crypto_nonce_from_iv_and_seqnum(memory.session_iv, memory.session_seq_num, nonce);

        // Decrypt
        std::array<uint8_t, 8> plaintext{};
        if (!delegate.crypto_aes_ccm_decrypt(
            memory.session_key,
            nonce,
            ciphertext.data(),
            ciphertext.size(),
            plaintext.data(),
            tag
            )) return report_error("PACKET_INVALID_AUTH", STATE_ARG_NAMES);
        //printf("p");
        delegate.tsp_recieved_new_packet(plaintext);
        TIMER_RESET();

        return false;
    }


    // ==============================
    // Implementation

    HostStateMachine::State HostStateMachine::getState() {
        return state;
    }

    bool TypeSafelyProtocol::HostStateMachine::tick(const typesafely_protocol_MessageWrapper *in_msg_wrapper, typesafely_protocol_MessageWrapper &out_msg_wrapper) {
        TransitionFnPtr f = nullptr;

        switch (state) {
            case HostStateMachine::State::Initial: {
                f = host_state_initial;
            } break;
            case HostStateMachine::State::ConnectRequestSent: {
                f = host_state_connect_request_sent;
            } break;
            case HostStateMachine::State::InitiatePairing: {
                f = host_state_initiate_pairing;
            } break;
            case HostStateMachine::State::InitiatePairingRequestSent: {
                f = host_state_initiate_pairing_request_sent;
            } break;
            case HostStateMachine::State::BeginAuthenticationRequestSent: {
                f = host_state_begin_authentication_request_sent;
            } break;
            case HostStateMachine::State::CommitmentExchangeRequestSent: {
                f = host_state_commitment_exchange_request_sent;
            } break;
            case HostStateMachine::State::NonceExchangeRequestSent: {
                f = host_state_nonce_exchange_request_sent;
            } break;
            case HostStateMachine::State::ParameterConfirmationRequestSent: {
                f = host_state_parameter_confirmation_request_sent;
            } break;
            case HostStateMachine::State::OpenSession: {
                f = host_state_open_session;
            } break;
            case HostStateMachine::State::OpenSessionRequestSent: {
                f = host_state_open_session_request_sent;
            } break;
            case HostStateMachine::State::SessionUpgradeRequestSent: {
                f = host_state_session_upgrade_request_sent;
            } break;
            case HostStateMachine::State::SessionOpen: {
                f = host_state_session_open;
            } break;
        }

        assert(f != nullptr);
        auto old_state = state;

        auto have_out_msg = f(in_msg_wrapper, out_msg_wrapper, memory, delegate, state, timer);

        if (have_out_msg) {
            TIMER_RESET();
        }

        if (state != old_state && state == HostStateMachine::State::SessionOpen) {
            delegate.encrypted_session_began();
        } else if (state != old_state && old_state == HostStateMachine::State::SessionOpen) {
            delegate.encrypted_session_ended();
        }

        return have_out_msg;
    }
}
