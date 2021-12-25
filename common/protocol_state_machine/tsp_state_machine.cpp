#include "tsp_state_machine.hpp"
#include "pb_encode.h"
#include "pb_decode.h"
#include "tsp_implementation_helpers.hpp"


bool TypeSafelyProtocol::Utilities::BufToArr(const pb_bytes_array_t * buf, uint8_t *arr_data, size_t arr_len) {
    if (arr_data == nullptr || buf == nullptr) return false;
    if (arr_len != buf->size) {
        fprintf(stderr, "Incorrect sizing in BufToArr: arr_len %zu, buf->size %hu.\n", arr_len, buf->size);
        return false;
    }

    memcpy(arr_data, buf->bytes, arr_len);

    return true;
}

bool TypeSafelyProtocol::Utilities::ArrToBuf(const uint8_t *arr_data, size_t arr_len, pb_bytes_array_t * buf, size_t buf_max_len) {
    if (arr_data == nullptr || buf == nullptr) return false;
    if (arr_len != buf_max_len || arr_len > PB_SIZE_MAX) {
        fprintf(stderr, "Incorrect sizing in ArrToBuf: arr_len %zu, buf_max_len %zu.\n", arr_len, buf_max_len);
        return false;
    }

    buf->size = static_cast<pb_size_t>(arr_len);
    memcpy(buf->bytes, arr_data, arr_len);

    return true;
}

int32_t TypeSafelyProtocol::StateMachine::tick(const uint8_t *in_buf, size_t in_len, uint8_t *out_buf, size_t out_buf_len) {
    typesafely_protocol_MessageWrapper msg_in{}, msg_out{};

    if (in_buf != nullptr) {
        int in_succ = decode_message(in_buf, in_len, msg_in);
        if (in_succ != 1) return in_succ;
    }

    bool have_out_msg = tick(in_buf != nullptr ? &msg_in : nullptr, msg_out);

    if (have_out_msg) {
        size_t used;
        int out_succ = encode_message(msg_out, out_buf, out_buf_len, &used);
        if (out_succ != 1) return out_succ;
        return static_cast<int32_t>(used);
    } else {
        return 0;
    }
}
