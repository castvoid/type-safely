from google.protobuf.message import Message
from cryptography.hazmat.primitives.asymmetric import ec
import cryptography.hazmat.backends
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
import os
import binascii


def wrapper_contains_type(wrapper: Message, message_type):
    if wrapper is None:
        return False

    field_name = "message_" + message_type.DESCRIPTOR.full_name.replace(".", "_")
    return wrapper.HasField(field_name)


def wrapper_get_contents(wrapper: Message, message_type=None):
    if message_type is not None:
        field_name = "message_" + message_type.DESCRIPTOR.full_name.replace(".", "_")
    else:
        field_name = wrapper.WhichOneof("message")

    return getattr(wrapper, field_name)


def crypto_generate_keypair():
    private: ec.EllipticCurvePrivateKeyWithSerialization = ec.generate_private_key(ec.SECP256R1(), cryptography.hazmat.backends.default_backend())
    public: ec.EllipticCurvePublicKey = private.public_key()

    ser_private = _crypto_private_to_bytes(private)
    ser_public = _crypto_public_to_bytes(public)
    return ser_private, ser_public


def crypto_get_nonce():
    return os.urandom(16)


def crypto_aes_cmac(k: bytes, m: bytes):
    cobj = CMAC.new(k, ciphermod=AES)
    cobj.update(m)
    return cobj.digest()


def crypto_ble_f4(u, v, x, z):
    # f4(U, V, X, Z) = AES-CMAC_X (U || V || Z)
    m = u + v + z
    k = x

    return crypto_aes_cmac(k, m)


def crypto_ble_f5(w, n1, n2, a1, a2):
    salt = binascii.unhexlify("6C88 8391 AAF5 A538 6037 0BDB 5A60 83BE".replace(" ", ""))
    keyid = binascii.unhexlify("62 74 6c 65".replace(" ", ""))
    t = crypto_aes_cmac(salt, w)

    def get_f5_counter(counter: int):
        m = counter.to_bytes(length=1, byteorder='big') + keyid + n1 + n2 + a1 + a2
        length = 256  # Why?
        m = m + length.to_bytes(length=2, byteorder='big')
        return crypto_aes_cmac(t, m)

    mackey = get_f5_counter(0)
    ltk = get_f5_counter(1)

    return mackey, ltk


def crypto_ble_f6(w, *args):
    return crypto_aes_cmac(w, b''.join(args))


def _crypto_private_from_bytes(data: bytes) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(
        private_value=int.from_bytes(bytes=data, byteorder='big'),
        curve=ec.SECP256R1(),
        backend=cryptography.hazmat.backends.default_backend()
    )


def _crypto_public_from_bytes(data: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicNumbers.from_encoded_point(
        curve=ec.SECP256R1(),
        data=data
    ).public_key(backend=cryptography.hazmat.backends.default_backend())


def _crypto_private_to_bytes(private: ec.EllipticCurvePrivateKeyWithSerialization) -> bytes:
    numbers: ec.EllipticCurvePrivateNumbers = private.private_numbers()
    v: int = numbers.private_value
    return v.to_bytes(length=32, byteorder='big')


def _crypto_public_to_bytes(public: ec.EllipticCurvePublicKey) -> bytes:
    numbers: ec.EllipticCurvePublicNumbers = public.public_numbers()
    return numbers.encode_point()


def crypto_derive_dhkey(private_bytes: bytes, public_bytes: bytes):
    private = _crypto_private_from_bytes(private_bytes)
    public = _crypto_public_from_bytes(public_bytes)

    shared_key = private.exchange(ec.ECDH(), public)

    return shared_key


if __name__ == "__main__":
    private_a_raw = binascii.unhexlify(
        "3f49f6d4 a3c55f38 74c9b3e3 d2103f50 4aff607b eb40b799 5899b8a6 cd3c1abd".replace(" ", ""))
    private_b_raw = binascii.unhexlify(
        "55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd".replace(" ", ""))

    private_b = _crypto_private_from_bytes(private_b_raw)
    public_b_raw = _crypto_public_to_bytes(private_b.public_key())

    print(crypto_derive_dhkey(private_a_raw, public_b_raw))
