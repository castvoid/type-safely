from collections import deque
from typing import Optional
from messages_pb2 import MessageWrapper
import messages_pb2
import messages_pairing_pb2
import messages_connection_pb2
import messages_session_pb2
from mypy_extensions import TypedDict
from google.protobuf.message import Message
from enum import Enum
import tsp_utils
import random
import binascii


# Memory
class KeysDict(TypedDict):
    private_host: bytes
    public_host: bytes
    private_device: bytes
    public_device: bytes


class ConnectionSetupDict(TypedDict):
    id_host: bytes
    id_device: bytes
    host_recognises_device_id: bool
    device_recognises_host_id: bool


class PairingSetupDict(TypedDict):
    keys: KeysDict
    dh_key: bytes
    nonce_host: bytes
    nonce_device: bytes
    passkey_host: bytes
    passkey_device: bytes
    commitment_host: bytes
    commitment_device: bytes
    ltk: bytes
    mac_key: bytes


class SessionSetupDict(TypedDict):
    keys: KeysDict


class TSProtocolDriverMemory(TypedDict):
    session_key: bytes
    connection_setup: ConnectionSetupDict
    pairing_setup: PairingSetupDict
    session_setup: SessionSetupDict


# Implementation
class TSPStateMachine:
    def __init__(self, initial_state, transitions: dict, input_queue: deque, output_queue: deque, ltk_store: dict):
        self.state = initial_state
        self.transitions = transitions
        self.memory = TSProtocolDriverMemory()
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.ltk_store = ltk_store

    def tick(self):
        msg_wrapper = None

        if self.input_queue:
            msg_wrapper = self.input_queue.pop()

        f = self.transitions.get(self.state)
        new_state, out_msg = f(msg_wrapper, self.ltk_store, self.memory)

        if new_state is not None:
            self.state = new_state

        if out_msg is not None:
            # Build MessageWrapper for raw message and put it on the queue
            field_name = "message_" + out_msg.DESCRIPTOR.full_name.replace(".", "_")
            out_msg_wrapped = MessageWrapper()
            getattr(out_msg_wrapped, field_name).CopyFrom(out_msg)
            self.output_queue.append(out_msg_wrapped)


def get_host_sm_states(id_host: bytes):
    class HostState(Enum):
        INITIAL = 1
        CONNECT_REQUEST_SENT = 2
        INITIATE_PAIRING = 7
        INITIATE_PAIRING_REQUEST_SENT = 3
        BEGIN_AUTHENTICATION_REQUEST_SENT = 4
        COMMITMENT_EXCHANGE_REQUEST_SENT = 5
        NONCE_EXCHANGE_REQUEST_SENT = 6
        PARAMETER_CONFIRMATION_REQUEST_SENT = 8
        OPEN_SESSION = 9
        OPEN_SESSION_REQUEST_SENT = 10
        SESSION_UPGRADE_REQUEST_SENT = 11
        AWAIT_OPEN_SESSION = 12
        SESSION_OPEN = 13

    def handle_unknown_message(input_msg) -> (HostState, Optional[Message]):
        if input_msg is None:
            return None, None
        if tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_pb2.Error):
            msg: messages_pb2.Error = tsp_utils.wrapper_get_contents(input_msg)
            print("Got error: {}. '{}'.".format(msg.error_type, msg.error_description))
            if msg.recovery_action == messages_pb2.Error.RESET_CONNECTION:
                return HostState.INITIAL, None
            elif msg.recovery_action == messages_pb2.Error.RESTART_PAIRING:
                return HostState.INITIATE_PAIRING, None
            elif msg.recovery_action == messages_pb2.Error.IGNORE:
                return None, None
        error_msg = messages_pb2.Error()
        error_msg.recovery_action = messages_pb2.Error.RESET_CONNECTION
        error_msg.error_type = "UNKNOWN_MESSAGE"
        return HostState.INITIAL, error_msg

    def state_initial(input_msg: Message, _ltk_store: dict, memory: TSProtocolDriverMemory) -> (HostState, Optional[Message]):
        if input_msg is not None:
            print("WARNING: read input message unexpectedly")

        memory["connection_setup"] = ConnectionSetupDict()
        memory["connection_setup"]["id_host"] = id_host
        out_msg = messages_connection_pb2.ConnectRequest()
        out_msg.id_host = id_host
        return HostState.CONNECT_REQUEST_SENT, out_msg

    def state_connect_request_sent(input_msg: Message, ltk_store: dict, memory: TSProtocolDriverMemory) -> (HostState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_connection_pb2.ConnectResponse):
            return handle_unknown_message(input_msg)

        connect_response: messages_connection_pb2.ConnectResponse = tsp_utils.wrapper_get_contents(input_msg)
        memory["connection_setup"]["id_device"] = connect_response.id_device
        memory["connection_setup"]["device_recognises_host_id"] = connect_response.device_recognises_host_id
        memory["connection_setup"]["host_recognises_device_id"] = connect_response.id_device in ltk_store

        if memory["connection_setup"]["device_recognises_host_id"] and memory["connection_setup"]["host_recognises_device_id"]:
            return HostState.OPEN_SESSION, None
        else:
            return HostState.INITIATE_PAIRING, None

    def state_initiate_pairing(input_msg: Message, _ltk_store: dict, memory: TSProtocolDriverMemory) -> (HostState, Optional[Message]):
        if input_msg is not None:
            print("WARNING: read input message unexpectedly")

        memory["pairing_setup"] = PairingSetupDict()
        memory["pairing_setup"]["keys"] = KeysDict()

        private, public = tsp_utils.crypto_generate_keypair()
        memory["pairing_setup"]["keys"]["private_host"], memory["pairing_setup"]["keys"]["public_host"] = private, public

        out_msg = messages_pairing_pb2.InitiatePairingRequest()
        out_msg.host_recognises_device_id = memory["connection_setup"]["host_recognises_device_id"]
        public_msg = messages_pairing_pb2.ECDHPublicKey()
        public_msg.public_key = public
        out_msg.host_ecdh_public_key.CopyFrom(public_msg)

        return HostState.INITIATE_PAIRING_REQUEST_SENT, out_msg

    def state_initiate_pairing_request_sent(input_msg: Message, _ltk_store: dict, memory: TSProtocolDriverMemory) -> (HostState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_pairing_pb2.InitiatePairingResponse):
            return handle_unknown_message(input_msg)

        pair_response: messages_pairing_pb2.InitiatePairingResponse = tsp_utils.wrapper_get_contents(input_msg)
        public_device_key = pair_response.device_ecdh_public_key.public_key
        memory["pairing_setup"]["keys"]["public_device"] = public_device_key

        dhkey = tsp_utils.crypto_derive_dhkey(
            private_bytes=memory["pairing_setup"]["keys"]["private_host"],
            public_bytes=memory["pairing_setup"]["keys"]["public_device"]
        )
        memory["pairing_setup"]["dh_key"] = dhkey

        pin = random.randint(0, 1000000)
        print("PIN: {}".format("{}".format(pin).zfill(6)))
        memory["pairing_setup"]["passkey_host"] = pin.to_bytes(16, byteorder='big')

        return HostState.BEGIN_AUTHENTICATION_REQUEST_SENT, messages_pairing_pb2.BeginAuthenticationRequest()

    def state_begin_authentication_request_sent(input_msg: Message, _ltk_store: dict, memory: TSProtocolDriverMemory) -> (HostState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_pairing_pb2.BeginAuthenticationResponse):
            return handle_unknown_message(input_msg)

        memory["pairing_setup"]["nonce_host"] = tsp_utils.crypto_get_nonce()

        msg = messages_pairing_pb2.CommitmentExchangeRequest()
        msg.host_commitment = tsp_utils.crypto_ble_f4(
            memory["pairing_setup"]["keys"]["public_host"],
            memory["pairing_setup"]["keys"]["public_device"],
            memory["pairing_setup"]["nonce_host"],
            memory["pairing_setup"]["passkey_host"]
        )

        return HostState.COMMITMENT_EXCHANGE_REQUEST_SENT, msg

    def state_commitment_exchange_request_sent(input_msg: Message, _ltk_store: dict, memory: TSProtocolDriverMemory) -> (HostState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_pairing_pb2.CommitmentExchangeResponse):
            return handle_unknown_message(input_msg)

        device_commit_msg: messages_pairing_pb2.CommitmentExchangeResponse = tsp_utils.wrapper_get_contents(input_msg)
        memory["pairing_setup"]["commitment_device"] = device_commit_msg.device_commitment

        msg = messages_pairing_pb2.NonceExchangeRequest()
        msg.host_nonce = memory["pairing_setup"]["nonce_host"]

        return HostState.NONCE_EXCHANGE_REQUEST_SENT, msg

    def state_nonce_exchange_request_sent(input_msg: Message, _ltk_store: dict, memory: TSProtocolDriverMemory) -> (HostState, Optional[Message]):
        # TODO: handle if they say our commit was wrong
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_pairing_pb2.NonceExchangeResponse):
            return handle_unknown_message(input_msg)

        device_nonce_msg: messages_pairing_pb2.NonceExchangeResponse = tsp_utils.wrapper_get_contents(input_msg)
        memory["pairing_setup"]["nonce_device"] = device_nonce_msg.device_nonce

        recomputed_device_commitment = tsp_utils.crypto_ble_f4(
            memory["pairing_setup"]["keys"]["public_device"],
            memory["pairing_setup"]["keys"]["public_host"],
            memory["pairing_setup"]["nonce_device"],
            memory["pairing_setup"]["passkey_host"]
        )

        if recomputed_device_commitment != memory["pairing_setup"]["commitment_device"]:
            print(
                "Device sent invalid commitment! Host expected {}.".format(
                    binascii.hexlify(bytearray(recomputed_device_commitment))
                )
            )

            msg = messages_pb2.Error()
            msg.recovery_action = msg.RESTART_PAIRING
            msg.error_type = "COMMITMENT_INVALID"
            msg.error_description = "Device sent an invalid commitment, possibly due to invalid PIN"
            return HostState.INITIATE_PAIRING, msg
        else:
            # MacKey || LTK = f5(DHKey, Na, Nb, IDa, IDb)
            # Ea = f6(MacKey, a-seen-b, Na, Nb, rb, IDa, IDb)
            # Send Ea
            mac_key, ltk = tsp_utils.crypto_ble_f5(
                memory["pairing_setup"]["dh_key"],
                memory["pairing_setup"]["nonce_host"],
                memory["pairing_setup"]["nonce_device"],
                memory["connection_setup"]["id_host"],
                memory["connection_setup"]["id_device"]
            )

            memory["pairing_setup"]["ltk"] = ltk
            memory["pairing_setup"]["mac_key"] = mac_key

            confirmation = tsp_utils.crypto_ble_f6(
                memory["pairing_setup"]["mac_key"],
                memory["pairing_setup"]["nonce_host"],
                memory["pairing_setup"]["nonce_device"],
                memory["pairing_setup"]["passkey_host"],
                memory["connection_setup"]["host_recognises_device_id"].to_bytes(length=1, byteorder='big'),
                memory["connection_setup"]["id_host"],
                memory["connection_setup"]["id_device"]
            )

            msg = messages_pairing_pb2.ParameterConfirmationRequest()
            msg.host_parameter_confirmation = confirmation

            return HostState.PARAMETER_CONFIRMATION_REQUEST_SENT, msg

    def state_parameter_confirmation_request_sent(input_msg: Message, ltk_store: dict, memory: TSProtocolDriverMemory) -> (HostState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_pairing_pb2.ParameterConfirmationResponse):
            return handle_unknown_message(input_msg)

        device_parameter_confirmation_msg: messages_pairing_pb2.ParameterConfirmationResponse = tsp_utils.wrapper_get_contents(input_msg)

        recomputed_confirmation = tsp_utils.crypto_ble_f6(
            memory["pairing_setup"]["mac_key"],
            memory["pairing_setup"]["nonce_device"],
            memory["pairing_setup"]["nonce_host"],
            memory["pairing_setup"]["passkey_host"],
            memory["connection_setup"]["device_recognises_host_id"].to_bytes(length=1, byteorder='big'),
            memory["connection_setup"]["id_device"],
            memory["connection_setup"]["id_host"],
        )

        if recomputed_confirmation != device_parameter_confirmation_msg.device_parameter_confirm:
            print(
                "Device sent invalid parameter confirmation! Host expected {}.".format(
                    binascii.hexlify(bytearray(recomputed_confirmation))
                )
            )

            msg = messages_pb2.Error()
            msg.recovery_action = msg.RESET_CONNECTION
            msg.error_type = "PARAMETER_CONFIRMATION_INVALID"
            msg.error_description = "Device sent an invalid parameter confirmation. This may indicate a MITM attack " \
                                    "trying to start a new pairing attempt! "
            return HostState.INITIAL, msg
        else:
            ltk_store[memory["connection_setup"]["id_device"]] = memory["pairing_setup"]["ltk"]
            return HostState.OPEN_SESSION, None

    def state_open_session(input_msg: Message, ltk_store: dict, memory: TSProtocolDriverMemory) -> (HostState, Optional[Message]):
        if input_msg is not None:
            print("WARNING: read input message unexpectedly")

        memory["session_setup"] = SessionSetupDict()
        memory["session_setup"]["keys"] = KeysDict()

        private, public = tsp_utils.crypto_generate_keypair()
        memory["session_setup"]["keys"]["private_host"], memory["session_setup"]["keys"]["public_host"] = private, public

        ltk = ltk_store[memory["connection_setup"]["id_device"]]

        # NOTE: LTK here isn't directly derived from ECDH, so we don't use a KDF!!
        auth_data = tsp_utils.crypto_aes_cmac(ltk,
                                              b"HOST" + memory["connection_setup"]["id_host"] + memory["connection_setup"]["id_device"] + public
                                              )

        msg = messages_session_pb2.OpenSessionRequest()
        msg.host_authentication_data = auth_data

        public_msg = messages_session_pb2.ECDHPublicKey()
        public_msg.public_key = public
        msg.host_ecdh_public_key.CopyFrom(public_msg)

        return HostState.OPEN_SESSION_REQUEST_SENT, msg

    def state_open_session_request_sent(input_msg: Message, ltk_store: dict, memory: TSProtocolDriverMemory) -> (HostState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_session_pb2.OpenSessionResponse):
            return handle_unknown_message(input_msg)

        open_session_resp: messages_session_pb2.OpenSessionResponse = tsp_utils.wrapper_get_contents(input_msg)
        memory["session_setup"]["keys"]["public_device"] = open_session_resp.device_ecdh_public_key.public_key
        auth_data: bytes = open_session_resp.device_authentication_data

        ltk = ltk_store[memory["connection_setup"]["id_device"]]
        recomputed_auth_data = tsp_utils.crypto_aes_cmac(ltk,
                                              b"KEYB" + memory["connection_setup"]["id_device"] + memory["connection_setup"]["id_host"] + open_session_resp.device_ecdh_public_key.public_key
                                              )

        if recomputed_auth_data != auth_data:
            print(
                "Device sent invalid auth data! Host expected {}.".format(
                    binascii.hexlify(bytearray(auth_data))
                )
            )

            msg = messages_pb2.Error()
            msg.recovery_action = msg.RESET_CONNECTION
            msg.error_type = "SESSION_AUTH_INVALID"
            msg.error_description = "Device sent an invalid authentication data."
            return HostState.INITIAL, msg
        else:
            dh_key = tsp_utils.crypto_derive_dhkey(
                private_bytes=memory["session_setup"]["keys"]["private_host"],
                public_bytes=memory["session_setup"]["keys"]["public_device"]
            )
            memory["session_key"] = dh_key

            msg = messages_session_pb2.UpgradeRequest()
            return HostState.SESSION_UPGRADE_REQUEST_SENT, msg

    def state_session_upgrade_request_sent(input_msg: Message, _ltk_store: dict, _memory: TSProtocolDriverMemory) -> (HostState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_session_pb2.UpgradeResponse):
            return handle_unknown_message(input_msg)

        return HostState.SESSION_OPEN, None

    def state_session_open(input_msg: Message, _ltk_store: dict, _memory: TSProtocolDriverMemory) -> (HostState, Optional[Message]):
        if input_msg is not None:
            print("WARNING: read input message unexpectedly")

        return HostState.SESSION_OPEN, None

    transitions = {
        HostState.INITIAL: state_initial,
        HostState.CONNECT_REQUEST_SENT: state_connect_request_sent,
        HostState.INITIATE_PAIRING: state_initiate_pairing,
        HostState.INITIATE_PAIRING_REQUEST_SENT: state_initiate_pairing_request_sent,
        HostState.BEGIN_AUTHENTICATION_REQUEST_SENT: state_begin_authentication_request_sent,
        HostState.COMMITMENT_EXCHANGE_REQUEST_SENT: state_commitment_exchange_request_sent,
        HostState.NONCE_EXCHANGE_REQUEST_SENT: state_nonce_exchange_request_sent,
        HostState.PARAMETER_CONFIRMATION_REQUEST_SENT: state_parameter_confirmation_request_sent,
        HostState.OPEN_SESSION: state_open_session,
        HostState.OPEN_SESSION_REQUEST_SENT: state_open_session_request_sent,
        HostState.SESSION_UPGRADE_REQUEST_SENT: state_session_upgrade_request_sent,
        HostState.SESSION_OPEN: state_session_open,
    }

    return HostState.INITIAL, transitions


def get_device_sm_states(id_device: bytes):
    class DeviceState(Enum):
        INITIAL = 1
        AWAIT_INITIAL_CONNECTION_STAGE = 2
        AWAIT_PAIRING_AUTHENTICATION_STAGE = 3
        AWAIT_COMMITMENT_EXCHANGE = 4
        AWAIT_NONCE_EXCHANGE = 5
        AWAIT_PARAMETER_CONFIRMATION = 6
        AWAIT_OPEN_SESSION = 8
        AWAIT_SESSION_UPGRADE = 9
        SESSION_OPEN = 10

    def handle_unknown_message(input_msg) -> (DeviceState, Optional[Message]):
        if input_msg is None:
            return None, None
        if tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_pb2.Error):
            msg: messages_pb2.Error = tsp_utils.wrapper_get_contents(input_msg)
            print("Got error: {}. '{}'.".format(msg.error_type, msg.error_description))
            if msg.recovery_action == messages_pb2.Error.RESET_CONNECTION:
                return DeviceState.INITIAL, None
            elif msg.recovery_action == messages_pb2.Error.RESTART_PAIRING:
                return DeviceState.AWAIT_INITIAL_CONNECTION_STAGE, None
            elif msg.recovery_action == messages_pb2.Error.IGNORE:
                return None, None
        error_msg = messages_pb2.Error()
        error_msg.recovery_action = messages_pb2.Error.RESET_CONNECTION
        error_msg.error_type = "UNKNOWN_MESSAGE"
        return DeviceState.INITIAL, error_msg

    def state_initial(input_msg: Message, ltk_store: dict, memory: TSProtocolDriverMemory) -> (DeviceState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_connection_pb2.ConnectRequest):
            return handle_unknown_message(input_msg)

        memory["connection_setup"] = ConnectionSetupDict()

        memory["connection_setup"]["id_device"] = id_device

        connect_request: messages_connection_pb2.ConnectRequest = tsp_utils.wrapper_get_contents(input_msg)
        memory["connection_setup"]["id_host"] = connect_request.id_host
        memory["connection_setup"]["device_recognises_host_id"] = connect_request.id_host in ltk_store

        out_msg = messages_connection_pb2.ConnectResponse()
        out_msg.id_device = memory["connection_setup"]["id_device"]
        out_msg.device_recognises_host_id = memory["connection_setup"]["device_recognises_host_id"]

        return DeviceState.AWAIT_INITIAL_CONNECTION_STAGE, out_msg

    def state_await_initial_connection_stage(input_msg: Message, ltk_store: dict, memory: TSProtocolDriverMemory) -> (DeviceState, Optional[Message]):
        # TODO: split this if's body into separate function
        if tsp_utils.wrapper_contains_type(wrapper=input_msg,message_type=messages_pairing_pb2.InitiatePairingRequest):
            memory["pairing_setup"] = PairingSetupDict()
            memory["pairing_setup"]["keys"] = KeysDict()

            pairing_request: messages_pairing_pb2.InitiatePairingRequest = tsp_utils.wrapper_get_contents(input_msg)
            memory["connection_setup"]["host_recognises_device_id"] = pairing_request.host_recognises_device_id
            memory["pairing_setup"]["keys"]["public_host"] = pairing_request.host_ecdh_public_key.public_key

            private, public = tsp_utils.crypto_generate_keypair()
            memory["pairing_setup"]["keys"]["private_device"], memory["pairing_setup"]["keys"][
                "public_device"] = private, public

            out_msg = messages_pairing_pb2.InitiatePairingResponse()
            public_msg = messages_pairing_pb2.ECDHPublicKey()
            public_msg.public_key = public
            out_msg.device_ecdh_public_key.CopyFrom(public_msg)

            memory["pairing_setup"]["dh_key"] = tsp_utils.crypto_derive_dhkey(
                private_bytes=memory["pairing_setup"]["keys"]["private_device"],
                public_bytes=memory["pairing_setup"]["keys"]["public_host"]
            )

            return DeviceState.AWAIT_PAIRING_AUTHENTICATION_STAGE, out_msg
        elif tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_session_pb2.OpenSessionRequest):
            return state_await_open_session(input_msg, ltk_store, memory)
        else:
            return handle_unknown_message(input_msg)

    def state_await_pairing_authentication_stage(input_msg: Message, _ltk_store: dict, memory: TSProtocolDriverMemory) -> (DeviceState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_pairing_pb2.BeginAuthenticationRequest):
            return handle_unknown_message(input_msg)

        pin = int(input("[Device] enter pin: ")).to_bytes(16, byteorder='big')
        memory["pairing_setup"]["passkey_device"] = pin

        out_msg = messages_pairing_pb2.BeginAuthenticationResponse()
        return DeviceState.AWAIT_COMMITMENT_EXCHANGE, out_msg

    def state_await_commitment_exchange(input_msg: Message, _ltk_store: dict, memory: TSProtocolDriverMemory) -> (DeviceState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_pairing_pb2.CommitmentExchangeRequest):
            return handle_unknown_message(input_msg)

        commitment_request: messages_pairing_pb2.CommitmentExchangeRequest = tsp_utils.wrapper_get_contents(input_msg)
        memory["pairing_setup"]["commitment_host"] = commitment_request.host_commitment

        memory["pairing_setup"]["nonce_device"] = tsp_utils.crypto_get_nonce()
        out_msg = messages_pairing_pb2.CommitmentExchangeResponse()
        out_msg.device_commitment = tsp_utils.crypto_ble_f4(
            memory["pairing_setup"]["keys"]["public_device"],
            memory["pairing_setup"]["keys"]["public_host"],
            memory["pairing_setup"]["nonce_device"],
            memory["pairing_setup"]["passkey_device"]
        )

        return DeviceState.AWAIT_NONCE_EXCHANGE, out_msg

    def state_await_nonce_exchange(input_msg: Message, _ltk_store: dict, memory: TSProtocolDriverMemory) -> (DeviceState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_pairing_pb2.NonceExchangeRequest):
            return handle_unknown_message(input_msg)

        # read nonce
        nonce_request_msg: messages_pairing_pb2.NonceExchangeRequest = tsp_utils.wrapper_get_contents(input_msg)
        memory["pairing_setup"]["nonce_host"] = nonce_request_msg.host_nonce

        # validate
        recomputed_host_commitment = tsp_utils.crypto_ble_f4(
            memory["pairing_setup"]["keys"]["public_host"],
            memory["pairing_setup"]["keys"]["public_device"],
            memory["pairing_setup"]["nonce_host"],
            memory["pairing_setup"]["passkey_device"]
        )

        # send our nonce or error
        if recomputed_host_commitment != memory["pairing_setup"]["commitment_host"]:
            print(
                "Host sent invalid commitment! Device expected {}.".format(
                    binascii.hexlify(bytearray(recomputed_host_commitment))
                )
            )

            msg = messages_pb2.Error()
            msg.recovery_action = msg.RESTART_PAIRING
            msg.error_type = "COMMITMENT_INVALID"
            msg.error_description = "Host sent an invalid commitment, likely due to invalid PIN being entered to device"
            # TODO: clear pairing memory
            return DeviceState.AWAIT_INITIAL_CONNECTION_STAGE, msg
        else:
            msg = messages_pairing_pb2.NonceExchangeResponse()
            msg.device_nonce = memory["pairing_setup"]["nonce_device"]

            mac_key, ltk = tsp_utils.crypto_ble_f5(
                memory["pairing_setup"]["dh_key"],
                memory["pairing_setup"]["nonce_host"],
                memory["pairing_setup"]["nonce_device"],
                memory["connection_setup"]["id_host"],
                memory["connection_setup"]["id_device"]
            )

            memory["pairing_setup"]["ltk"] = ltk
            memory["pairing_setup"]["mac_key"] = mac_key

            return DeviceState.AWAIT_PARAMETER_CONFIRMATION, msg

    def state_await_parameter_confirmation(input_msg: Message, ltk_store: dict, memory: TSProtocolDriverMemory) -> (DeviceState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_pairing_pb2.ParameterConfirmationRequest):
            return handle_unknown_message(input_msg)

        confirmation_request: messages_pairing_pb2.ParameterConfirmationRequest = tsp_utils.wrapper_get_contents(input_msg)

        recomputed_confirmation = tsp_utils.crypto_ble_f6(
            memory["pairing_setup"]["mac_key"],
            memory["pairing_setup"]["nonce_host"],
            memory["pairing_setup"]["nonce_device"],
            memory["pairing_setup"]["passkey_device"],
            memory["connection_setup"]["host_recognises_device_id"].to_bytes(length=1, byteorder='big'),
            memory["connection_setup"]["id_host"],
            memory["connection_setup"]["id_device"]
        )

        if recomputed_confirmation != confirmation_request.host_parameter_confirmation:
            print(
                "Host sent invalid parameter confirmation! Device expected {}.".format(
                    binascii.hexlify(bytearray(recomputed_confirmation))
                )
            )

            msg = messages_pb2.Error()
            msg.recovery_action = msg.RESET_CONNECTION
            msg.error_type = "PARAMETER_CONFIRMATION_INVALID"
            msg.error_description = "Host sent an invalid parameter confirmation. This may indicate a MITM attack " \
                                    "trying to start a new pairing attempt! "
            return DeviceState.INITIAL, msg
        else:
            confirmation = tsp_utils.crypto_ble_f6(
                memory["pairing_setup"]["mac_key"],
                memory["pairing_setup"]["nonce_device"],
                memory["pairing_setup"]["nonce_host"],
                memory["pairing_setup"]["passkey_device"],
                memory["connection_setup"]["device_recognises_host_id"].to_bytes(length=1, byteorder='big'),
                memory["connection_setup"]["id_device"],
                memory["connection_setup"]["id_host"],
            )

            conf_msg = messages_pairing_pb2.ParameterConfirmationResponse()
            conf_msg.device_parameter_confirm = confirmation

            ltk_store[memory["connection_setup"]["id_host"]] = memory["pairing_setup"]["ltk"]

            return DeviceState.AWAIT_OPEN_SESSION, conf_msg

    def state_await_open_session(input_msg: Message, ltk_store: dict, memory: TSProtocolDriverMemory) -> (DeviceState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_session_pb2.OpenSessionRequest):
            return handle_unknown_message(input_msg)

        memory["session_setup"] = SessionSetupDict()
        memory["session_setup"]["keys"] = KeysDict()

        open_session_req: messages_session_pb2.OpenSessionRequest = tsp_utils.wrapper_get_contents(input_msg)
        memory["session_setup"]["keys"]["public_host"] = open_session_req.host_ecdh_public_key.public_key
        ltk = ltk_store[memory["connection_setup"]["id_host"]]

        recomputed_host_auth_data = tsp_utils.crypto_aes_cmac(ltk,
                                              b"HOST" + memory["connection_setup"]["id_host"] + memory["connection_setup"]["id_device"] + open_session_req.host_ecdh_public_key.public_key
                                              )

        if recomputed_host_auth_data != open_session_req.host_authentication_data:
            print(
                "Host sent invalid auth data! Device expected {}.".format(
                    binascii.hexlify(bytearray(open_session_req.host_authentication_data))
                )
            )

            msg = messages_pb2.Error()
            msg.recovery_action = msg.RESET_CONNECTION
            msg.error_type = "SESSION_AUTH_INVALID"
            msg.error_description = "Host sent an invalid authentication data."
            return DeviceState.INITIAL, msg
        else:
            private, public = tsp_utils.crypto_generate_keypair()
            memory["session_setup"]["keys"]["private_device"], memory["session_setup"]["keys"]["public_device"] = private, public

            msg = messages_session_pb2.OpenSessionResponse()
            auth_data = tsp_utils.crypto_aes_cmac(ltk,
                                              b"KEYB" + memory["connection_setup"]["id_device"] + memory["connection_setup"]["id_host"] + public
                                              )
            msg.device_authentication_data = auth_data

            public_msg = messages_session_pb2.ECDHPublicKey()
            public_msg.public_key = public
            msg.device_ecdh_public_key.CopyFrom(public_msg)
            return DeviceState.AWAIT_SESSION_UPGRADE, msg

    def state_await_session_upgrade(input_msg: Message, _ltk_store: dict, _memory: TSProtocolDriverMemory) -> (DeviceState, Optional[Message]):
        if not tsp_utils.wrapper_contains_type(wrapper=input_msg, message_type=messages_session_pb2.UpgradeRequest):
            return handle_unknown_message(input_msg)

        return DeviceState.SESSION_OPEN, messages_session_pb2.UpgradeResponse()

    def state_session_open(input_msg: Message, _ltk_store: dict, _memory: TSProtocolDriverMemory) -> (DeviceState, Optional[Message]):
        if input_msg is not None:
            print("WARNING: read input message unexpectedly")

        return DeviceState.SESSION_OPEN, None

    transitions = {
        DeviceState.INITIAL: state_initial,
        DeviceState.AWAIT_INITIAL_CONNECTION_STAGE: state_await_initial_connection_stage,
        DeviceState.AWAIT_PAIRING_AUTHENTICATION_STAGE: state_await_pairing_authentication_stage,
        DeviceState.AWAIT_COMMITMENT_EXCHANGE: state_await_commitment_exchange,
        DeviceState.AWAIT_NONCE_EXCHANGE: state_await_nonce_exchange,
        DeviceState.AWAIT_PARAMETER_CONFIRMATION: state_await_parameter_confirmation,
        DeviceState.AWAIT_OPEN_SESSION: state_await_open_session,
        DeviceState.AWAIT_SESSION_UPGRADE: state_await_session_upgrade,
        DeviceState.SESSION_OPEN: state_session_open,
    }

    return DeviceState.INITIAL, transitions
