#pragma once

#include "tsp_state_machine.hpp"

namespace TypeSafelyProtocol {
    class DeviceStateMachine : public StateMachine {
        public:
        enum class State {
            Initial,
            AwaitInitialConnectionStage,
            AwaitPairingAuthenticationStage,
            SpinUntilPinReady,
            AwaitCommitmentExchange,
            AwaitNonceExchange,
            AwaitParameterConfirmation,
            AwaitOpenSession,
            AwaitSessionUpgrade,
            SessionOpen
        };
        
        DeviceStateMachine(
            IDelegate &delegate,
            std::array<uint8_t, len_entity_id> id_device,
            StateMachineMemory memory = {},
            State initial_state = State::Initial
            ) : StateMachine(delegate, memory)
              , state(initial_state)
              {
                  this->memory.connection.id_device = id_device;
              };

        DeviceStateMachine& operator= (const DeviceStateMachine &other) {
            this->delegate = other.delegate;
            this->memory = other.memory;
            this->state = other.state;
            return *this;
        }

        bool tick(const typesafely_protocol_MessageWrapper *in_msg_wrapper, typesafely_protocol_MessageWrapper &out_msg_wrapper) override;
        bool sessionEncryptPacket(const std::array<std::uint8_t, 8> &packet, std::array<uint8_t, 64> &packet_enc, size_t *packet_enc_used);

        State getState();
        void reset();

        protected:
        State state;
    };
}
