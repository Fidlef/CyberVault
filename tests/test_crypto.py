import pytest

from crypto_core import HEADER, MAGIC, VaultError, decrypt_bytes, encrypt_bytes

FAST_N = 2**10


def test_round_trip_binary_data():
    data = b"synthetic\x00file\xffcontents"
    assert decrypt_bytes(encrypt_bytes(data, "correct horse battery", n=FAST_N), "correct horse battery", n=FAST_N) == data


def test_same_input_produces_different_envelopes():
    first = encrypt_bytes(b"same", "correct horse battery", n=FAST_N)
    second = encrypt_bytes(b"same", "correct horse battery", n=FAST_N)
    assert first != second


def test_wrong_password_is_rejected():
    envelope = encrypt_bytes(b"secret", "correct horse battery", n=FAST_N)
    with pytest.raises(VaultError, match="wrong or the file was changed"):
        decrypt_bytes(envelope, "different password", n=FAST_N)


def test_tampering_is_rejected():
    envelope = bytearray(encrypt_bytes(b"secret", "correct horse battery", n=FAST_N))
    envelope[-1] ^= 1
    with pytest.raises(VaultError, match="changed"):
        decrypt_bytes(bytes(envelope), "correct horse battery", n=FAST_N)


def test_header_has_magic_and_version():
    envelope = encrypt_bytes(b"content", "correct horse battery", n=FAST_N)
    magic, version, _salt, _nonce = HEADER.unpack(envelope[: HEADER.size])
    assert magic == MAGIC and version == 1


def test_truncated_file_is_rejected():
    with pytest.raises(VaultError, match="too short"):
        decrypt_bytes(b"CVLT", "correct horse battery", n=FAST_N)

