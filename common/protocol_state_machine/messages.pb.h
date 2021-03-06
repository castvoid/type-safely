/* Automatically generated nanopb header */
/* Generated by nanopb-0.3.9.2 at Mon Jan 28 21:43:08 2019. */

#ifndef PB_TYPESAFELY_PROTOCOL_MESSAGES_PB_H_INCLUDED
#define PB_TYPESAFELY_PROTOCOL_MESSAGES_PB_H_INCLUDED
#include <pb.h>

#include "messages-connection.pb.h"

#include "messages-pairing.pb.h"

#include "messages-session.pb.h"

/* @@protoc_insertion_point(includes) */
#if PB_PROTO_HEADER_VERSION != 30
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Enum definitions */
typedef enum _typesafely_protocol_Error_RecoveryAction {
    typesafely_protocol_Error_RecoveryAction_RESET_CONNECTION = 0,
    typesafely_protocol_Error_RecoveryAction_RESTART_PAIRING = 1,
    typesafely_protocol_Error_RecoveryAction_IGNORE = 2
} typesafely_protocol_Error_RecoveryAction;
#define _typesafely_protocol_Error_RecoveryAction_MIN typesafely_protocol_Error_RecoveryAction_RESET_CONNECTION
#define _typesafely_protocol_Error_RecoveryAction_MAX typesafely_protocol_Error_RecoveryAction_IGNORE
#define _typesafely_protocol_Error_RecoveryAction_ARRAYSIZE ((typesafely_protocol_Error_RecoveryAction)(typesafely_protocol_Error_RecoveryAction_IGNORE+1))

/* Struct definitions */
typedef struct _typesafely_protocol_DebugLog {
    char text[512];
/* @@protoc_insertion_point(struct:typesafely_protocol_DebugLog) */
} typesafely_protocol_DebugLog;

typedef struct _typesafely_protocol_Error {
    char error_type[64];
    char error_description[512];
    typesafely_protocol_Error_RecoveryAction recovery_action;
/* @@protoc_insertion_point(struct:typesafely_protocol_Error) */
} typesafely_protocol_Error;

typedef struct _typesafely_protocol_MessageWrapper {
    pb_size_t which_message;
    union {
        typesafely_protocol_pairing_CommitmentExchangeResponse message_typesafely_protocol_pairing_CommitmentExchangeResponse;
        typesafely_protocol_Error message_typesafely_protocol_Error;
        typesafely_protocol_DebugLog message_typesafely_protocol_DebugLog;
        typesafely_protocol_connection_ConnectRequest message_typesafely_protocol_connection_ConnectRequest;
        typesafely_protocol_connection_ConnectResponse message_typesafely_protocol_connection_ConnectResponse;
        typesafely_protocol_pairing_InitiatePairingRequest message_typesafely_protocol_pairing_InitiatePairingRequest;
        typesafely_protocol_pairing_InitiatePairingResponse message_typesafely_protocol_pairing_InitiatePairingResponse;
        typesafely_protocol_pairing_BeginAuthenticationRequest message_typesafely_protocol_pairing_BeginAuthenticationRequest;
        typesafely_protocol_pairing_BeginAuthenticationResponse message_typesafely_protocol_pairing_BeginAuthenticationResponse;
        typesafely_protocol_pairing_CommitmentExchangeRequest message_typesafely_protocol_pairing_CommitmentExchangeRequest;
        typesafely_protocol_pairing_NonceExchangeRequest message_typesafely_protocol_pairing_NonceExchangeRequest;
        typesafely_protocol_pairing_NonceExchangeResponse message_typesafely_protocol_pairing_NonceExchangeResponse;
        typesafely_protocol_pairing_ParameterConfirmationRequest message_typesafely_protocol_pairing_ParameterConfirmationRequest;
        typesafely_protocol_pairing_ParameterConfirmationResponse message_typesafely_protocol_pairing_ParameterConfirmationResponse;
        typesafely_protocol_session_OpenSessionRequest message_typesafely_protocol_session_OpenSessionRequest;
        typesafely_protocol_session_OpenSessionResponse message_typesafely_protocol_session_OpenSessionResponse;
        typesafely_protocol_session_UpgradeRequest message_typesafely_protocol_session_UpgradeRequest;
        typesafely_protocol_session_UpgradeResponse message_typesafely_protocol_session_UpgradeResponse;
        typesafely_protocol_session_Packet message_typesafely_protocol_session_Packet;
    } message;
/* @@protoc_insertion_point(struct:typesafely_protocol_MessageWrapper) */
} typesafely_protocol_MessageWrapper;

/* Default values for struct fields */

/* Initializer values for message structs */
#define typesafely_protocol_Error_init_default   {"", "", _typesafely_protocol_Error_RecoveryAction_MIN}
#define typesafely_protocol_DebugLog_init_default {""}
#define typesafely_protocol_MessageWrapper_init_default {0, {typesafely_protocol_pairing_CommitmentExchangeResponse_init_default}}
#define typesafely_protocol_Error_init_zero      {"", "", _typesafely_protocol_Error_RecoveryAction_MIN}
#define typesafely_protocol_DebugLog_init_zero   {""}
#define typesafely_protocol_MessageWrapper_init_zero {0, {typesafely_protocol_pairing_CommitmentExchangeResponse_init_zero}}

/* Field tags (for use in manual encoding/decoding) */
#define typesafely_protocol_DebugLog_text_tag    1
#define typesafely_protocol_Error_error_type_tag 1
#define typesafely_protocol_Error_error_description_tag 2
#define typesafely_protocol_Error_recovery_action_tag 3
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_CommitmentExchangeResponse_tag 11
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_Error_tag 1001
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_DebugLog_tag 1002
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_connection_ConnectRequest_tag 1003
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_connection_ConnectResponse_tag 1004
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_InitiatePairingRequest_tag 1005
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_InitiatePairingResponse_tag 1006
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_BeginAuthenticationRequest_tag 1007
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_BeginAuthenticationResponse_tag 1008
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_CommitmentExchangeRequest_tag 1009
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_NonceExchangeRequest_tag 1011
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_NonceExchangeResponse_tag 1012
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_ParameterConfirmationRequest_tag 1013
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_pairing_ParameterConfirmationResponse_tag 1014
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_session_OpenSessionRequest_tag 1015
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_session_OpenSessionResponse_tag 1016
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_session_UpgradeRequest_tag 1017
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_session_UpgradeResponse_tag 1018
#define typesafely_protocol_MessageWrapper_message_typesafely_protocol_session_Packet_tag 1019

/* Struct field encoding specification for nanopb */
extern const pb_field_t typesafely_protocol_Error_fields[4];
extern const pb_field_t typesafely_protocol_DebugLog_fields[2];
extern const pb_field_t typesafely_protocol_MessageWrapper_fields[20];

/* Maximum encoded size of messages (where known) */
#define typesafely_protocol_Error_size           583
#define typesafely_protocol_DebugLog_size        515
#define typesafely_protocol_MessageWrapper_size  587

/* Message IDs (where set with "msgid" option) */
#ifdef PB_MSGID

#define MESSAGES_MESSAGES \


#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
/* @@protoc_insertion_point(eof) */

#endif
