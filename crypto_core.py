"""Small, versioned envelope for password-derived AES-256-GCM encryption."""

from __future__ import annotations

import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"CVLT"
VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
DEFAULT_SCRYPT_N = 2**15
HEADER = struct.Struct(">4sB16s12s")
AAD = MAGIC + bytes([VERSION])


class VaultError(ValueError):
    """Raised when an encrypted envelope cannot be validated."""


def _password_bytes(password: str) -> bytes:
    if not isinstance(password, str) or not password:
        raise VaultError("A password is required.")
    return password.encode("utf-8")


def derive_key(password: str, salt: bytes, *, n: int = DEFAULT_SCRYPT_N) -> bytes:
    """Derive a 256-bit key using a memory-hard password KDF."""
    kdf = Scrypt(salt=salt, length=32, n=n, r=8, p=1)
    return kdf.derive(_password_bytes(password))


def encrypt_bytes(plaintext: bytes, password: str, *, n: int = DEFAULT_SCRYPT_N) -> bytes:
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt, n=n)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, AAD)
    return HEADER.pack(MAGIC, VERSION, salt, nonce) + ciphertext


def decrypt_bytes(envelope: bytes, password: str, *, n: int = DEFAULT_SCRYPT_N) -> bytes:
    if not isinstance(envelope, bytes):
        raise TypeError("envelope must be bytes")
    if len(envelope) < HEADER.size + TAG_SIZE:
        raise VaultError("The file is too short to be a CyberVault envelope.")
    magic, version, salt, nonce = HEADER.unpack(envelope[: HEADER.size])
    if magic != MAGIC:
        raise VaultError("The file does not have the CyberVault signature.")
    if version != VERSION:
        raise VaultError(f"Unsupported CyberVault version: {version}.")
    key = derive_key(password, salt, n=n)
    try:
        return AESGCM(key).decrypt(nonce, envelope[HEADER.size :], AAD)
    except InvalidTag as exc:
        raise VaultError("Decryption failed: the password is wrong or the file was changed.") from exc

