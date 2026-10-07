"""完成标签的第三方核验。运行确认仍用 62 字节完成帧，这条路径不进百万台更新。"""

from __future__ import annotations

import struct

from .crypto import sm3
from .package import merkle_root
from .sm9id import enrollment_id, sign_message, verify_message


def completion_message(zone: int, tid: int, epoch: int, tag: bytes) -> bytes:
    if len(tag) != 16:
        raise ValueError("完成标签长度错误")
    return b"ACKP" + struct.pack(">IQI", zone, tid, epoch) + tag


def sign_completion(terminal) -> tuple[bytes, bytes]:
    tag = terminal.completion_tag()
    message = completion_message(terminal.zone_id, terminal.tid, terminal.epoch, tag)
    identity = enrollment_id(terminal.area, terminal.zone_id, terminal.tid & 0xFFFF)
    signature = sign_message(terminal.sm9_user, terminal.sm9_public, identity, message)
    return tag, signature


def audit_root(items: list[tuple[int, bytes, bytes]]) -> bytes:
    ordered = sorted(items, key=lambda item: item[0])
    leaves = [sm3(struct.pack(">Q", tid) + tag + signature) for tid, tag, signature in ordered]
    if not leaves:
        raise ValueError("确认审计为空")
    return merkle_root(leaves)


def verify_completion_audit(
    sm9_public: bytes,
    area: int,
    zone: int,
    epoch: int,
    items: list[tuple[int, int, bytes, bytes]],
    root: bytes,
) -> bool:
    """items 是 (台区内序号, 终端号, 标签, SM9 签名)。"""
    try:
        folded = audit_root([(tid, tag, signature) for _local, tid, tag, signature in items])
    except Exception:
        return False
    if folded != root:
        return False
    for local, tid, tag, signature in items:
        identity = enrollment_id(area, zone, local)
        message = completion_message(zone, tid, epoch, tag)
        if not verify_message(sm9_public, identity, message, signature):
            return False
    return True
