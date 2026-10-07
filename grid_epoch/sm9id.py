"""接入认证用的 SM9 标识签名。不进入纪元报文，也不进入百万台更新。

现行标准是 GM/T 0044.2-2025，2026 年 1 月 5 日发布，2026 年 7 月 1 日实施。
这里对照的是该算法公开示例：标识 Alice、消息 “Chinese IBS standard”、
以及 GM/T 0044.2-2016 附录里的 h 和 S。没有把未读到的 2025 版差异写成已经符合。
"""

from __future__ import annotations

import struct

import gmalg

HID = b"\x01"
_STANDARD_MASTER = bytes.fromhex("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
_STANDARD_PUBLIC = bytes.fromhex(
    "049F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408"
    "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32"
    "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25"
    "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D"
)
_STANDARD_USER = bytes.fromhex(
    "04A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820"
    "78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3"
)
_STANDARD_MESSAGE = b"Chinese IBS standard"
_STANDARD_H = bytes.fromhex("823C4B21E4BD2DFE1ED92C606653E996668563152FC33F55D7BFBB9BD9705ADB")
_STANDARD_S = bytes.fromhex(
    "0473BF96923CE58B6AD0E13E9643A406D8EB98417C50EF1B29CEF9ADB48B6D598C"
    "856712F1C2E0968AB7769F42A99586AED139D5B8B3E15891827CC2ACED9BAA05"
)


def enrollment_id(area: int, zone: int, local: int) -> bytes:
    if not 0 <= local <= 0xFFFF:
        raise ValueError("台区内序号必须落在 16 位")
    return b"GEID" + struct.pack(">IIH", area, zone, local)


def enrollment_message(challenge: bytes, tid: int, epoch: int) -> bytes:
    if len(challenge) != 16:
        raise ValueError("接入挑战必须是 16 字节")
    return b"ENR1" + challenge + struct.pack(">QI", tid, epoch)


def _master_bytes(master: bytes) -> bytes:
    if not master or len(master) > 32:
        raise ValueError("SM9 签名主私钥必须是 32 字节")
    return master.rjust(32, b"\x00")


def master_public(master: bytes) -> bytes:
    return gmalg.SM9KGC(hid_s=HID).generate_mpk_sign(_master_bytes(master))


def new_master() -> tuple[bytes, bytes]:
    secret, public = gmalg.SM9KGC(hid_s=HID).generate_keypair_sign()
    secret = _master_bytes(secret)
    return secret, public


def user_sign_key(master: bytes, identity: bytes) -> bytes:
    return gmalg.SM9KGC(hid_s=HID, msk_s=_master_bytes(master)).generate_sk_sign(identity)


def sign_message(user_key: bytes, public: bytes, identity: bytes, message: bytes) -> bytes:
    signer = gmalg.SM9(hid_s=HID, mpk_s=public, sk_s=user_key, uid=identity)
    digest, point = signer.sign(message)
    return digest + point


def verify_message(public: bytes, identity: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) < 33:
        return False
    try:
        checker = gmalg.SM9(hid_s=HID, mpk_s=public, uid=identity)
        return bool(checker.verify(message, signature[:32], signature[32:]))
    except Exception:
        return False


def standard_sample_verifies() -> bool:
    """公开示例：Alice 对 Chinese IBS standard 的签名能通过，换标识则不能。"""
    public = master_public(_STANDARD_MASTER)
    if public != _STANDARD_PUBLIC:
        return False
    if user_sign_key(_STANDARD_MASTER, b"Alice") != _STANDARD_USER:
        return False
    signature = _STANDARD_H + _STANDARD_S
    if not verify_message(_STANDARD_PUBLIC, b"Alice", _STANDARD_MESSAGE, signature):
        return False
    return not verify_message(_STANDARD_PUBLIC, b"Bob", _STANDARD_MESSAGE, signature)
