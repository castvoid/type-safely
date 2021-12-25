#pragma once

#include "tsp_state_machine.hpp"
#include <chrono>

namespace TypeSafelyProtocol {
    class HostStateMachine : public StateMachine {
        public:
        enum class State {
            Initial,
            ConnectRequestSent,
            InitiatePairing,
            InitiatePairingRequestSent,
            BeginAuthenticationRequestSent,
            CommitmentExchangeRequestSent,
            NonceExchangeRequestSent,
            ParameterConfirmationRequestSent,
            OpenSession,
            OpenSessionRequestSent,
            SessionUpgradeRequestSent,
            SessionOpen
        };
        
        HostStateMachine(
            IDelegate &delegate,
            std::array<uint8_t, len_entity_id> id_host,
            StateMachineMemory memory = {},
            State initial_state = State::Initial
            ) : StateMachine(delegate, memory)
              , state(initial_state)
              , timer()
              {
                this->memory.connection.id_host = id_host;
              };

        bool tick(const typesafely_protocol_MessageWrapper *in_msg_wrapper, typesafely_protocol_MessageWrapper &out_msg_wrapper) override;
        
        State getState();

        protected:
        State state;
        std::chrono::time_point<std::chrono::system_clock> timer;
    };
}
