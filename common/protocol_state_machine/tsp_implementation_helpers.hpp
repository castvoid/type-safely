#pragma once
#include <messages.pb.h>
#include <array>
#include <cstring>
#include "tsp_state_machine.hpp"


enum MessageType {
    MessageTypeError = typesafely_protocol_MessageWrapper_message_typesafely_protocol_Error_tag,
    MessageTypeDebugLog = typesafely_protocol_MessageWrapper_message_typesafely_protocol_DebugLog_tag,
    MessageTypeConnectionConnectRequest = typesafely_protocol_MessageWrapper_message_typesafely_protocol_connection_ConnectRequest_tag,
    MessageTypeConnectionConnectResponse = typesafely_protocol_MessageWrapper_message_typesafely_protocol_connection_ConnectResponse_tag,
    MessageTypePairingInitiatePairingRequest = typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_InitiatePairingRequest_tag,
    MessageTypePairingInitiatePairingResponse = typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_InitiatePairingResponse_tag,
    MessageTypePairingBeginAuthenticationRequest = typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_BeginAuthenticationRequest_tag,
    MessageTypePairingBeginAuthenticationResponse = typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_BeginAuthenticationResponse_tag,
    MessageTypePairingCommitmentExchangeRequest = typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_CommitmentExchangeRequest_tag,
    MessageTypePairingCommitmentExchangeResponse = typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_CommitmentExchangeResponse_tag,
    MessageTypePairingNonceExchangeRequest = typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_NonceExchangeRequest_tag,
    MessageTypePairingNonceExchangeResponse = typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_NonceExchangeResponse_tag,
    MessageTypePairingParameterConfirmationRequest = typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_ParameterConfirmationRequest_tag,
    MessageTypePairingParameterConfirmationResponse = typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_ParameterConfirmationResponse_tag,
    MessageTypeSessionOpenSessionRequest = typesafely_protocol_MessageWrapper_message_typesafely_protocol_session_OpenSessionRequest_tag,
    MessageTypeSessionOpenSessionResponse = typesafely_protocol_MessageWrapper_message_typesafely_protocol_session_OpenSessionResponse_tag,
    MessageTypeSessionUpgradeRequest = typesafely_protocol_MessageWrapper_message_typesafely_protocol_session_UpgradeRequest_tag,
    MessageTypeSessionUpgradeResponse = typesafely_protocol_MessageWrapper_message_typesafely_protocol_session_UpgradeResponse_tag,
    MessageTypeSessionPacket = typesafely_protocol_MessageWrapper_message_typesafely_protocol_session_Packet_tag,
};

#define COPY_BUF_TO_ARR(buf, vec) TypeSafelyProtocol::Utilities::BufToArr((const pb_bytes_array_t *)&buf, vec.data(), vec.size())
#define COPY_ARR_TO_BUF(vec, buf) TypeSafelyProtocol::Utilities::ArrToBuf(vec.data(), vec.size(), (pb_bytes_array_t *)&buf, sizeof(buf.bytes)/sizeof(buf.bytes[0]))

#define ENSURE_IN_MSG_TYPE_OR_ERROR(type) \
do { \
    if (in_msg_wrapper == nullptr) return false; \
    if (!message_has_type(in_msg_wrapper, type)) { \
     return handle_unexpected_message(STATE_ARG_NAMES); \
    } \
} while (0)

void crypto_ec_pubkey_get_x(const std::array<uint8_t, 65> &pubkey, std::array<uint8_t, 32> &x_coord);
void crypto_ec_pubkey_get_x(const std::array<uint8_t, 33> &pubkey, std::array<uint8_t, 32> &x_coord);
void crypto_ec_pubkey_get_x(const std::array<uint8_t, 32> &pubkey, std::array<uint8_t, 32> &x_coord);

bool crypto_ble_f4(
    TypeSafelyProtocol::StateMachine::IDelegate &delegate,
    const std::array<uint8_t, 32> &u,
    const std::array<uint8_t, 32> &v,
    const std::array<uint8_t, 16> &x,
    const std::array<uint8_t, 16> &z, // XXX: altered from 8 bits to 128
    std::array<uint8_t, 16> &mac
);

bool crypto_ble_f5(
    TypeSafelyProtocol::StateMachine::IDelegate &delegate,
    const std::array<uint8_t, 32> &w,
    const std::array<uint8_t, 16> &n1,
    const std::array<uint8_t, 16> &n2,
    const std::array<uint8_t, 7> &a1,
    const std::array<uint8_t, 7> &a2,
    std::array<uint8_t, 16> &mac_upper,
    std::array<uint8_t, 16> &mac_lower
);

bool crypto_ble_f6(
    TypeSafelyProtocol::StateMachine::IDelegate &delegate,
    const std::array<uint8_t, TypeSafelyProtocol::len_mac_key> &mac_key,
    const std::array<uint8_t, TypeSafelyProtocol::len_pairing_nonce> &nonce_1,
    const std::array<uint8_t, TypeSafelyProtocol::len_pairing_nonce> &nonce_2,
    const std::array<uint8_t, TypeSafelyProtocol::len_passkey> &passkey,
    const std::array<uint8_t, 1> &recognises,
    const std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id_1,
    const std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id_2,
    std::array<uint8_t, 16> &mac
);

bool crypto_gen_session_auth(
    TypeSafelyProtocol::StateMachine::IDelegate &delegate,
    const std::array<uint8_t, TypeSafelyProtocol::len_ltk> &ltk,
    const std::array<uint8_t, 4> &role,
    const std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id_self,
    const std::array<uint8_t, TypeSafelyProtocol::len_entity_id> &id_other,
    const std::array<uint8_t, TypeSafelyProtocol::len_public_key> &pubkey,
    std::array<uint8_t, 16> &mac
);

bool crypto_generate_session_key(
    TypeSafelyProtocol::StateMachine::IDelegate &delegate,
    const std::array<uint8_t, TypeSafelyProtocol::len_private_key> &key_private,
    const std::array<uint8_t, TypeSafelyProtocol::len_public_key> &key_public,
    std::array<uint8_t, TypeSafelyProtocol::len_session_key> &session_key,
    std::array<uint8_t, TypeSafelyProtocol::len_session_iv> &session_iv
);

bool crypto_nonce_from_iv_and_seqnum(
    const std::array<uint8_t, 13> &iv,
    uint64_t seqnum,
    std::array<uint8_t, 13> &nonce
);

int encode_message(const typesafely_protocol_MessageWrapper &msg, uint8_t *out_buf, size_t out_buf_len, size_t *out_len);
int decode_message(const uint8_t *in_buf, size_t in_len, typesafely_protocol_MessageWrapper &msg);
