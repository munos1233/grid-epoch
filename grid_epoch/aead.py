"""SM4-CTR + HMAC-SM3。加密密钥和认证密钥从覆盖密钥分开派生。"""

from __future__ import annotations

import hmac
import os
import struct

from .crypto import hmac_sm3, kdf, sm4_block


class CryptoError(Exception):
    pass


def aead_keys(key: bytes) -> tuple[bytes, bytes]:
    if len(key) != 16:
        raise ValueError("AEAD 密钥为 16 字节")
    return kdf(key + b"AENC", 16), kdf(key + b"AMAC", 16)


def _ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    out = bytearray()
    counter = int.from_bytes(iv, "big")
    offset = 0
    while offset < len(data):
        stream = sm4_block(key, counter.to_bytes(16, "big"))
        take = min(16, len(data) - offset)
        for i in range(take):
            out.append(data[offset + i] ^ stream[i])
        counter = (counter + 1) & ((1 << 128) - 1)
        offset += take
    return bytes(out)


def seal(key: bytes, plaintext: bytes) -> bytes:
    enc, mac_key = aead_keys(key)
    iv = os.urandom(16)
    ct = _ctr(enc, iv, plaintext)
    mac = hmac_sm3(mac_key, b"\x01" + iv + ct)
    return iv + struct.pack(">H", len(ct)) + ct + mac


def open_aead(key: bytes, sealed: bytes) -> bytes:
    if len(key) != 16 or len(sealed) < 16 + 2 + 32:
        raise CryptoError("密文格式错误")
    enc, mac_key = aead_keys(key)
    iv = sealed[:16]
    ct_len = struct.unpack_from(">H", sealed, 16)[0]
    if 18 + ct_len + 32 != len(sealed):
        raise CryptoError("密文长度不匹配")
    ct = sealed[18:18 + ct_len]
    mac = sealed[18 + ct_len:]
    calc = hmac_sm3(mac_key, b"\x01" + iv + ct)
    if not hmac.compare_digest(calc, mac):
        raise CryptoError("完整性校验失败")
    return _ctr(enc, iv, ct)
