from tsp_driver import get_device_sm_states, get_host_sm_states, TSPStateMachine
from collections import deque

queue_output = deque()
queue_input = deque()

host_initial, host_transitions = get_host_sm_states(b"host")
host_sm = TSPStateMachine(
    initial_state=host_initial,
    transitions=host_transitions,
    input_queue=queue_input,
    output_queue=queue_output,
    ltk_store={}
)

device_initial, device_transitions = get_device_sm_states(b"device")
device_sm = TSPStateMachine(
    initial_state=device_initial,
    transitions=device_transitions,
    input_queue=queue_output,
    output_queue=queue_input,
    ltk_store={}
)

while True:
    input()
    print("==HOST==")
    state_old = host_sm.state
    host_sm.tick()
    state_new = host_sm.state
    print("{} -> {}".format(state_old, state_new))
    print("Output: {}".format(queue_output[-1] if queue_output else "-None-"))

    input()
    print("==DEVICE==")
    state_old = device_sm.state
    device_sm.tick()
    state_new = device_sm.state
    print("{} -> {}".format(state_old, state_new))
    print("Output: {}".format(queue_input[-1] if queue_input else "-None-"))
