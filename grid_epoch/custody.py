"""主密钥和纪元随机数做成 2-of-3 门限。任意两份能恢复，单独一份不能。"""

from __future__ import annotations

import secrets

from .aead import open_aead, seal
from .crypto import kdf
from .errors import AuthFailed


def seal_masters(
    mk_mgmt: bytes,
    mk_biz: bytes,
    sm9_master: bytes,
    password_a: str,
    password_b: str,
) -> tuple[bytes, bytes, bytes]:
    if len(mk_mgmt) != 32 or len(mk_biz) != 32 or len(sm9_master) != 32:
        raise ValueError("主密钥必须是 32 字节")
    _check_passwords(password_a, password_b)
    first, second, offline = split_secret(mk_mgmt + mk_biz + sm9_master)
    return _seal_share(password_a, first), _seal_share(password_b, second), offline


def seal_epoch_nonces(
    auth_nonce: bytes, biz_nonce: bytes, password_a: str, password_b: str
) -> tuple[bytes, bytes, bytes]:
    """纪元随机数的双人口令托管。第三份是离线分片，不留在发布进程的长期状态里。"""
    if len(auth_nonce) != 16 or len(biz_nonce) != 16:
        raise ValueError("纪元随机数必须是 16 字节")
    _check_passwords(password_a, password_b)
    first, second, offline = split_secret(auth_nonce + biz_nonce)
    return _seal_share(password_a, first), _seal_share(password_b, second), offline


def open_epoch_nonces(
    blob_a: bytes, blob_b: bytes, password_a: str, password_b: str
) -> tuple[bytes, bytes]:
    secret = _restore_sealed(blob_a, blob_b, password_a, password_b, 32, "纪元随机数")
    return secret[:16], secret[16:]


def open_epoch_with_offline(
    blob: bytes, password: str, offline: bytes
) -> tuple[bytes, bytes]:
    secret = _restore_one_sealed(blob, password, offline, 32, "纪元随机数")
    return secret[:16], secret[16:]


def restore_masters(
    blob_a: bytes, blob_b: bytes, password_a: str, password_b: str
) -> tuple[bytes, bytes, bytes]:
    secret = _restore_sealed(blob_a, blob_b, password_a, password_b, 96, "主密钥")
    return secret[:32], secret[32:64], secret[64:]


def restore_masters_offline(
    blob: bytes, password: str, offline: bytes
) -> tuple[bytes, bytes, bytes]:
    secret = _restore_one_sealed(blob, password, offline, 96, "主密钥")
    return secret[:32], secret[32:64], secret[64:]


def split_secret(secret: bytes) -> tuple[bytes, bytes, bytes]:
    """GF(256) 上的一次多项式。分片是序号字节接上各字节的取值。"""
    if not secret:
        raise ValueError("秘密不能为空")
    coefficients = secrets.token_bytes(len(secret))
    shares = []
    for index in (1, 2, 3):
        body = bytes(_xor(_mul(coefficient, index), value) for value, coefficient in zip(secret, coefficients))
        shares.append(bytes([index]) + body)
    return shares[0], shares[1], shares[2]


def combine_shares(left: bytes, right: bytes) -> bytes:
    if len(left) < 2 or len(left) != len(right) or left[0] == right[0] or left[0] not in (1, 2, 3) or right[0] not in (1, 2, 3):
        raise AuthFailed("门限分片无法恢复")
    x1, y1 = left[0], left[1:]
    x2, y2 = right[0], right[1:]
    gap = x1 ^ x2
    scale_1 = _div(x2, gap)
    scale_2 = _div(x1, gap)
    return bytes(_xor(_mul(value_1, scale_1), _mul(value_2, scale_2)) for value_1, value_2 in zip(y1, y2))


def _restore_sealed(blob_a: bytes, blob_b: bytes, password_a: str, password_b: str, size: int, label: str) -> bytes:
    try:
        left = _open_share(password_a, blob_a)
        right = _open_share(password_b, blob_b)
        secret = combine_shares(left, right)
    except Exception as exc:
        raise AuthFailed(f"两份口令才能恢复{label}") from exc
    if len(secret) != size:
        raise AuthFailed(f"{label}分片长度不对")
    return secret


def _restore_one_sealed(blob: bytes, password: str, offline: bytes, size: int, label: str) -> bytes:
    try:
        secret = combine_shares(_open_share(password, blob), offline)
    except Exception as exc:
        raise AuthFailed(f"一份口令和离线分片才能恢复{label}") from exc
    if len(secret) != size:
        raise AuthFailed(f"{label}分片长度不对")
    return secret


def _check_passwords(password_a: str, password_b: str) -> None:
    if not password_a or not password_b or password_a == password_b:
        raise ValueError("两份口令必须不同且非空")


def _seal_share(password: str, share: bytes) -> bytes:
    salt = secrets.token_bytes(16)
    return salt + seal(_password_key(password, salt), share)


def _open_share(password: str, blob: bytes) -> bytes:
    if len(blob) < 16:
        raise AuthFailed("分片被截断")
    salt, sealed = blob[:16], blob[16:]
    return open_aead(_password_key(password, salt), sealed)


def _password_key(password: str, salt: bytes) -> bytes:
    return kdf(b"CUST" + salt + password.encode("utf-8"), 16)


def _mul(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        right >>= 1
        carry = left & 0x80
        left = (left << 1) & 0xFF
        if carry:
            left ^= 0x1B
    return result


def _div(numerator: int, denominator: int) -> int:
    if denominator == 0:
        raise AuthFailed("门限分片无法恢复")
    inverse = 1
    base = denominator
    exponent = 254
    while exponent:
        if exponent & 1:
            inverse = _mul(inverse, base)
        base = _mul(base, base)
        exponent >>= 1
    return _mul(numerator, inverse)


def _xor(left: int, right: int) -> int:
    return left ^ right
