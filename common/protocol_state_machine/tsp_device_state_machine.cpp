#include "tsp_device_state_machine.hpp"
#include <vector>
#include <string>
#include <cassert>
#include <messages.pb.h>
#include "tsp_implementation_helpers.hpp"
#include "messages.pb.h"

// TODO: move this to being a struct that has a reference passed round
#define STATE_ARGS const typesafely_protocol_MessageWrapper *in_msg_wrapper, typesafely_protocol_MessageWrapper &out_wrapper, StateMachine::StateMachineMemory &memory, StateMachine::IDelegate &delegate, DeviceStateMachine::State &state
#define STATE_ARG_NAMES in_msg_wrapper, out_wrapper, memory, delegate, state


namespace TypeSafelyProtocol{
    using TransitionFnPtr = bool (*)(STATE_ARGS);

    static bool device_state_initial(STATE_ARGS);
    static bool device_state_await_open_session(STATE_ARGS);

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
                state = DeviceStateMachine::State::AwaitInitialConnectionStage;
                break;
            case typesafely_protocol_Error_RecoveryAction_RESET_CONNECTION:
            default:
                state = DeviceStateMachine::State::Initial;
                break;
        }

        return true;
    }

    static bool handle_unexpected_message(STATE_ARGS) {
        if (message_has_type(in_msg_wrapper, MessageTypeConnectionConnectRequest)) return device_state_initial(STATE_ARG_NAMES);
        else if (message_has_type(in_msg_wrapper, MessageTypeError)) {
            auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_Error;
            delegate.tsp_sm_received_error(in_msg.error_type);

            switch (in_msg.recovery_action) {
                case typesafely_protocol_Error_RecoveryAction_IGNORE:
                    return false;
                case typesafely_protocol_Error_RecoveryAction_RESTART_PAIRING:
                    state = DeviceStateMachine::State::AwaitInitialConnectionStage;
                    return false;
                case typesafely_protocol_Error_RecoveryAction_RESET_CONNECTION:
                default:
                    state = DeviceStateMachine::State::Initial;
                    return false;
            }
            return false;
        } else {
            return report_error("UNKNOWN_MESSAGE", STATE_ARG_NAMES, typesafely_protocol_Error_RecoveryAction_RESET_CONNECTION);
        }

        return false;
    }


    // ==============================
    // State machine states

    static bool device_state_initial(STATE_ARGS) {
        // Check input message type is a MessageTypeConnectionConnectRequest
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypeConnectionConnectRequest);

        // Extract id_host from the message
        auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_connection_ConnectRequest;
        if (!COPY_BUF_TO_ARR(in_msg.id_host, memory.connection.id_host)) return report_error("INCORRECT_SIZE", STATE_ARG_NAMES);

        // Create a new response message & store the device id
        typesafely_protocol_connection_ConnectResponse out_msg = {};
        if (!COPY_ARR_TO_BUF(memory.connection.id_device, out_msg.id_device)) return report_error("INCORRECT_SIZE", STATE_ARG_NAMES);

        // check if we recognise the host's id and put that in the message
        memory.connection.device_recognises_host_id = delegate.does_recognise_id(memory.connection.id_host);
        out_msg.device_recognises_host_id = memory.connection.device_recognises_host_id;

        
        out_wrapper.which_message = MessageTypeConnectionConnectResponse;
        out_wrapper.message.message_typesafely_protocol_connection_ConnectResponse = out_msg;
        state = DeviceStateMachine::State::AwaitInitialConnectionStage;
        return true;
    }


    static bool device_state_await_initial_connection_stage(STATE_ARGS) {
        if (message_has_type(in_msg_wrapper, MessageTypePairingInitiatePairingRequest)) {
            auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_pairing_InitiatePairingRequest;
            memory.connection.host_recognises_device_id = in_msg.host_recognises_device_id;
            if (!COPY_BUF_TO_ARR(in_msg.host_ecdh_public_key.public_key, memory.pairing.keys.public_host)) return report_error("INCORRECT_SIZE", STATE_ARG_NAMES);

            delegate.crypto_generate_ecdh_keypair(
                memory.pairing.keys.private_device,
                memory.pairing.keys.public_device
                );
            delegate.crypto_derive_dhkey(
                memory.pairing.keys.private_device,
                memory.pairing.keys.public_host,
                memory.pairing.dh_key
                );

            typesafely_protocol_pairing_InitiatePairingResponse out_msg = {};
            if (!COPY_ARR_TO_BUF(memory.pairing.keys.public_device, out_msg.device_ecdh_public_key.public_key)) return report_error("INCORRECT_SIZE", STATE_ARG_NAMES);

            
            out_wrapper.which_message = MessageTypePairingInitiatePairingResponse;
            out_wrapper.message.message_typesafely_protocol_pairing_InitiatePairingResponse = out_msg;
            state = DeviceStateMachine::State::AwaitPairingAuthenticationStage;
            return true;
        } else if (message_has_type(in_msg_wrapper, MessageTypeSessionOpenSessionRequest)) {
            memory.connection.host_recognises_device_id = true;
            return device_state_await_open_session(STATE_ARG_NAMES);
        } else {
            // TODO: remove this next line
            if (in_msg_wrapper == nullptr) return false;
            return handle_unexpected_message(STATE_ARG_NAMES);
        }
    }


    static bool device_state_await_pairing_authentication_stage(STATE_ARGS) {
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypePairingBeginAuthenticationRequest);

        state = DeviceStateMachine::State::SpinUntilPinReady;
        // TODO ensure success
        delegate.begin_passkey_entry();

        return false;
    }


    static bool device_state_spin_until_pin_ready(STATE_ARGS) {
        if (in_msg_wrapper != nullptr) return handle_unexpected_message(STATE_ARG_NAMES);

        // Fetch the passkey from the delegate, or spin in the current state
        if (!delegate.get_entered_passkey(memory.pairing.passkey_device)) return false;

        typesafely_protocol_pairing_BeginAuthenticationResponse out_msg = {};
        
        out_wrapper.which_message = MessageTypePairingBeginAuthenticationResponse;
        out_wrapper.message.message_typesafely_protocol_pairing_BeginAuthenticationResponse = out_msg;
        state = DeviceStateMachine::State::AwaitCommitmentExchange;
        return true;
    }


    static bool device_state_await_commitment_exchange(STATE_ARGS) {
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypePairingCommitmentExchangeRequest);

        auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_pairing_CommitmentExchangeRequest;
        COPY_BUF_TO_ARR(in_msg.host_commitment, memory.pairing.commitment_host);

        // Generate a nonce
        if (!delegate.get_random_bytes(memory.pairing.nonce_device.data(), memory.pairing.nonce_device.size())) return report_error("INTERNAL", STATE_ARG_NAMES);

        // Calculate commitment
        std::array<uint8_t, 32> pubkey_x_host{}, pubkey_x_device{};
        crypto_ec_pubkey_get_x(memory.pairing.keys.public_host, pubkey_x_host);
        crypto_ec_pubkey_get_x(memory.pairing.keys.public_device, pubkey_x_device);

        bool commitment_calc_succeeded = crypto_ble_f4(
            delegate,
            pubkey_x_device,
            pubkey_x_host,
            memory.pairing.nonce_device,
            memory.pairing.passkey_device,
            memory.pairing.commitment_device
        );

        if (!commitment_calc_succeeded) return report_error("INTERNAL", STATE_ARG_NAMES);

        typesafely_protocol_pairing_CommitmentExchangeResponse out_msg = {};
        COPY_ARR_TO_BUF(memory.pairing.commitment_device, out_msg.device_commitment);
        
        out_wrapper.which_message = MessageTypePairingCommitmentExchangeResponse;
        out_wrapper.message.message_typesafely_protocol_pairing_CommitmentExchangeResponse = out_msg;
        state = DeviceStateMachine::State::AwaitNonceExchange;
        return true;
    }


    static bool device_state_await_nonce_exchange(STATE_ARGS) {
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypePairingNonceExchangeRequest);

        auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_pairing_NonceExchangeRequest;
        COPY_BUF_TO_ARR(in_msg.host_nonce, memory.pairing.nonce_host);

        std::array<uint8_t, 32> pubkey_x_host{}, pubkey_x_device{};
        crypto_ec_pubkey_get_x(memory.pairing.keys.public_host, pubkey_x_host);
        crypto_ec_pubkey_get_x(memory.pairing.keys.public_device, pubkey_x_device);

        std::array<uint8_t, len_commitment> recalculated_host_commitment{};
        bool commitment_recalc_succeeded = crypto_ble_f4(
            delegate,
            pubkey_x_host,
            pubkey_x_device,
            memory.pairing.nonce_host,
            memory.pairing.passkey_device,
            recalculated_host_commitment
        );
        if (!commitment_recalc_succeeded) return report_error("INTERNAL", STATE_ARG_NAMES);

        bool recomputed_commitment_matches = (recalculated_host_commitment == memory.pairing.commitment_host);

        if (!recomputed_commitment_matches) {
            fprintf(stderr, "Host sent invalid commitment!\n"); // TODO: don't use fprintf on uC
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

            typesafely_protocol_pairing_NonceExchangeResponse out_msg = {};
            COPY_ARR_TO_BUF(memory.pairing.nonce_device, out_msg.device_nonce);
            
            out_wrapper.which_message = MessageTypePairingNonceExchangeResponse;
            out_wrapper.message.message_typesafely_protocol_pairing_NonceExchangeResponse = out_msg;
            state = DeviceStateMachine::State::AwaitParameterConfirmation;
            return true;
        }
    }


    static bool device_state_await_parameter_confirmation(STATE_ARGS) {
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypePairingParameterConfirmationRequest);

        auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_pairing_ParameterConfirmationRequest;
        std::array<uint8_t, 16> host_confirmation_recieved{};
        COPY_BUF_TO_ARR(in_msg.host_parameter_confirmation, host_confirmation_recieved);
        std::array<uint8_t, 16> host_confirmation_recomputed{};
        bool recompute_host_f6_succeded = crypto_ble_f6(
            delegate,
            memory.pairing.mac_key,
            memory.pairing.nonce_host,
            memory.pairing.nonce_device,
            memory.pairing.passkey_device,
            {static_cast<uint8_t>(memory.connection.host_recognises_device_id)},
            memory.connection.id_host,
            memory.connection.id_device,
            host_confirmation_recomputed
        );
        if (!recompute_host_f6_succeded) return report_error("INTERNAL", STATE_ARG_NAMES);

        if (host_confirmation_recieved != host_confirmation_recomputed) {
            fprintf(stderr, "Host sent invalid confirmation!\n");
            return report_error("INVALID_CONFIRMATION", STATE_ARG_NAMES, typesafely_protocol_Error_RecoveryAction_RESTART_PAIRING);
        } else {
            // TODO: move?
            delegate.store_ltk_for_id(memory.connection.id_host, memory.pairing.ltk);

            // Compute our confirmation f6
            std::array<uint8_t, 16> device_confirmation{};
            bool compute_device_f6_succeded = crypto_ble_f6(
                delegate,
                memory.pairing.mac_key,
                memory.pairing.nonce_device,
                memory.pairing.nonce_host,
                memory.pairing.passkey_device,
                {static_cast<uint8_t>(memory.connection.device_recognises_host_id)},
                memory.connection.id_device,
                memory.connection.id_host,
                device_confirmation
            );
            if (!compute_device_f6_succeded) return report_error("INTERNAL", STATE_ARG_NAMES);

            // Put out confirmation in a message
            typesafely_protocol_pairing_ParameterConfirmationResponse out_msg = {};
            COPY_ARR_TO_BUF(device_confirmation, out_msg.device_parameter_confirm);

            // Goto AWAIT_OPEN SESSION
            out_wrapper.which_message = MessageTypePairingParameterConfirmationResponse;
            out_wrapper.message.message_typesafely_protocol_pairing_ParameterConfirmationResponse = out_msg;
            state = DeviceStateMachine::State::AwaitOpenSession;
            return true;
        }
    }


    static bool device_state_await_open_session(STATE_ARGS) {
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypeSessionOpenSessionRequest);

        auto in_msg = in_msg_wrapper->message.message_typesafely_protocol_session_OpenSessionRequest;

        std::array<uint8_t, 16> host_auth_data{};
        COPY_BUF_TO_ARR(in_msg.host_ecdh_public_key.public_key, memory.session.keys.public_host);
        COPY_BUF_TO_ARR(in_msg.host_authentication_data, host_auth_data);

        std::array<uint8_t, len_ltk> ltk{};
        delegate.ltk_for_id(memory.connection.id_host, ltk);

        std::array<uint8_t, 16> recomputed_host_auth_data{};
        crypto_gen_session_auth(
            delegate,
            ltk,
            {'H', 'O', 'S', 'T'}, // TODO: non-ascii!
            memory.connection.id_host,
            memory.connection.id_device,
            memory.session.keys.public_host,
            recomputed_host_auth_data
        );

        if (recomputed_host_auth_data != host_auth_data) {
            fprintf(stderr, "Host sent invalid authentication data!\n");
            return report_error("INVALID_AUTH", STATE_ARG_NAMES, typesafely_protocol_Error_RecoveryAction_RESTART_PAIRING);
        } else {
            delegate.crypto_generate_ecdh_keypair(memory.session.keys.private_device, memory.session.keys.public_device);

            std::array<uint8_t, 16> device_auth{};
            bool could_compute_auth = crypto_gen_session_auth(
                delegate,
                ltk,
                {'K', 'E', 'Y', 'B'}, // TODO: non-ascii!
                memory.connection.id_device,
                memory.connection.id_host,
                memory.session.keys.public_device,
                device_auth
            );
            if (!could_compute_auth) report_error("INTERNAL", STATE_ARG_NAMES);

            typesafely_protocol_session_OpenSessionResponse out_msg = {};
            COPY_ARR_TO_BUF(device_auth, out_msg.device_authentication_data);
            COPY_ARR_TO_BUF(memory.session.keys.public_device, out_msg.device_ecdh_public_key.public_key);

            
            out_wrapper.which_message = MessageTypeSessionOpenSessionResponse;
            out_wrapper.message.message_typesafely_protocol_session_OpenSessionResponse = out_msg;
            state = DeviceStateMachine::State::AwaitSessionUpgrade;
            return true;
        }

    }


    static bool device_state_await_session_upgrade(STATE_ARGS) {
        ENSURE_IN_MSG_TYPE_OR_ERROR(MessageTypeSessionUpgradeRequest);

        if (!crypto_generate_session_key(
            delegate,
            memory.session.keys.private_device,
            memory.session.keys.public_host,
            memory.session_key,
            memory.session_iv
        )) return report_error("INTERNAL", STATE_ARG_NAMES);

        out_wrapper.which_message = MessageTypeSessionUpgradeResponse;
        out_wrapper.message.message_typesafely_protocol_session_UpgradeResponse = {};
        state = DeviceStateMachine::State::SessionOpen;
        return true;
    }


    static bool device_state_session_open(STATE_ARGS) {
        if (in_msg_wrapper != nullptr) return handle_unexpected_message(STATE_ARG_NAMES);

        return false;
    }


    // ==============================
    // Implementation

    DeviceStateMachine::State DeviceStateMachine::getState() {
        return state;
    }

    void DeviceStateMachine::reset() {
        auto old_state = state;

        state = DeviceStateMachine::State::Initial;
        if (old_state == DeviceStateMachine::State::SessionOpen) {
            delegate.encrypted_session_ended();
        }
    }

    bool TypeSafelyProtocol::DeviceStateMachine::tick(const typesafely_protocol_MessageWrapper *in_msg_wrapper, typesafely_protocol_MessageWrapper &out_msg_wrapper) {
        TransitionFnPtr f = nullptr;

        switch (state) {
            case DeviceStateMachine::State::Initial: {
                f = device_state_initial;
            } break;
            case DeviceStateMachine::State::AwaitInitialConnectionStage: {
                f = device_state_await_initial_connection_stage;
            } break;
            case DeviceStateMachine::State::AwaitPairingAuthenticationStage: {
                f = device_state_await_pairing_authentication_stage;
            } break;
            case DeviceStateMachine::State::SpinUntilPinReady: {
                f = device_state_spin_until_pin_ready;
            } break;
            case DeviceStateMachine::State::AwaitCommitmentExchange: {
                f = device_state_await_commitment_exchange;
            } break;
            case DeviceStateMachine::State::AwaitNonceExchange: {
                f = device_state_await_nonce_exchange;
            } break;
            case DeviceStateMachine::State::AwaitParameterConfirmation: {
                f = device_state_await_parameter_confirmation;
            } break;
            case DeviceStateMachine::State::AwaitOpenSession: {
                f = device_state_await_open_session;
            } break;
            case DeviceStateMachine::State::AwaitSessionUpgrade: {
                f = device_state_await_session_upgrade;
            } break;
            case DeviceStateMachine::State::SessionOpen: {
                f = device_state_session_open;
            } break;
        }

        assert(f != nullptr);
        auto old_state = state;

        auto ret = f(in_msg_wrapper, out_msg_wrapper, memory, delegate, state);

        if (state != old_state && state == DeviceStateMachine::State::SessionOpen) {
            delegate.encrypted_session_began();
        } else if (state != old_state && old_state == DeviceStateMachine::State::SessionOpen) {
            delegate.encrypted_session_ended();
        }

        return ret;
    }

    bool DeviceStateMachine::sessionEncryptPacket(const std::array<std::uint8_t, 8> &packet, std::array<uint8_t, 64> &packet_enc, size_t *packet_enc_used) {
        if (state != DeviceStateMachine::State::SessionOpen) return false;

        std::array<uint8_t, 13> nonce{};
        if (!crypto_nonce_from_iv_and_seqnum(memory.session_iv, memory.session_seq_num, nonce)) return false;

        std::array<uint8_t, 8> ciphertext{};
        assert(ciphertext.size() == packet.size());
        std::array<uint8_t, 16> tag{};

        const bool could_encrypt = delegate.crypto_aes_ccm_encrypt(
            memory.session_key,
            nonce,
            packet.data(),
            packet.size(),
            ciphertext.data(),
            tag
        );
        if (!could_encrypt) return false;

        typesafely_protocol_MessageWrapper wrapper = {};
        wrapper.which_message = MessageTypeSessionPacket;
        auto &out_msg = wrapper.message.message_typesafely_protocol_session_Packet;
        if (!COPY_ARR_TO_BUF(ciphertext, out_msg.ciphertext)) return false;
        if (!COPY_ARR_TO_BUF(tag, out_msg.tag)) return false;
        out_msg.sequence_num = memory.session_seq_num;

        int succeeded_encoding = encode_message(wrapper, packet_enc.data(), packet_enc.size(), packet_enc_used);
        if (!succeeded_encoding) return false;

        memory.session_seq_num++;
        return true;
    }
}
