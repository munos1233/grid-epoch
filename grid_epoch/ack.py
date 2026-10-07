"""台区更新确认帧。完成与否由业务密钥标签的异或决定，链路 MAC 只证明帧来自该台区。"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .crypto import hmac_sm3
from .errors import ProtocolError


ZALL = b"ZALL"
ZEXC = b"ZEXC"
ZDET = b"ZDET"
FLAG_MISSING = 1
FLAG_PRESENT = 2
TAG_LEN = 16
MAC_LEN = 32
# 魔数 4 + 台区 4 + 纪元 4 + 台数 2 + 标签 16 + 链路 MAC 32
ZALL_LEN = 62


def xor_tags(tags: list[bytes]) -> bytes:
    folded = bytearray(TAG_LEN)
    for tag in tags:
        if len(tag) != TAG_LEN:
            raise ProtocolError("完成标签长度错误")
        for index, value in enumerate(tag):
            folded[index] ^= value
    return bytes(folded)


def _seal(link: bytes, body: bytes) -> bytes:
    return body + hmac_sm3(link, body)


def encode_zall(zone_id: int, epoch: int, count: int, tag_xor: bytes, link: bytes) -> bytes:
    if not 0 < count <= 0xFFFF:
        raise ProtocolError("完成帧台数不合法")
    if len(tag_xor) != TAG_LEN:
        raise ProtocolError("完成标签长度错误")
    body = ZALL + struct.pack(">IIH", zone_id, epoch, count) + tag_xor
    return _seal(link, body)


def encode_zexc(
    zone_id: int,
    epoch: int,
    flag: int,
    locals_: list[int],
    tag_xor: bytes,
    link: bytes,
) -> bytes:
    if flag not in (FLAG_MISSING, FLAG_PRESENT):
        raise ProtocolError("差额帧种类不合法")
    if len(locals_) > 0xFFFF or len(tag_xor) != TAG_LEN:
        raise ProtocolError("差额帧不合法")
    body = bytearray(ZEXC + struct.pack(">IIBH", zone_id, epoch, flag, len(locals_)))
    for local in locals_:
        if not 0 <= local <= 0xFFFF:
            raise ProtocolError("台区内序号不合法")
        body += struct.pack(">H", local)
    body += tag_xor
    return _seal(link, bytes(body))


def encode_zdet(zone_id: int, epoch: int, items: list[tuple[int, bytes]], link: bytes) -> bytes:
    if len(items) > 0xFFFF:
        raise ProtocolError("明细超过台区容量")
    body = bytearray(ZDET + struct.pack(">IIH", zone_id, epoch, len(items)))
    for local, tag in items:
        if not 0 <= local <= 0xFFFF or len(tag) != TAG_LEN:
            raise ProtocolError("明细不合法")
        body += struct.pack(">H", local) + tag
    return _seal(link, bytes(body))


@dataclass(frozen=True)
class ZoneReport:
    kind: str
    zone_id: int
    epoch: int
    count: int
    flag: int
    locals_: tuple[int, ...]
    tag_xor: bytes
    body: bytes
    mac: bytes


@dataclass(frozen=True)
class ZoneDetail:
    zone_id: int
    epoch: int
    items: tuple[tuple[int, bytes], ...]
    body: bytes
    mac: bytes


def _split_mac(token: bytes, minimum: int) -> tuple[bytes, bytes]:
    if len(token) < minimum or len(token) < MAC_LEN:
        raise ProtocolError("更新确认格式错误")
    return token[:-MAC_LEN], token[-MAC_LEN:]


def parse_report(token: bytes) -> ZoneReport:
    if token.startswith(ZALL):
        body, mac = _split_mac(token, ZALL_LEN)
        if len(token) != ZALL_LEN:
            raise ProtocolError("更新确认长度不匹配")
        zone_id, epoch, count = struct.unpack_from(">IIH", body, 4)
        tag_xor = body[14:30]
        return ZoneReport("full", zone_id, epoch, count, 0, (), tag_xor, body, mac)
    if not token.startswith(ZEXC):
        raise ProtocolError("更新确认格式错误")
    body, mac = _split_mac(token, 4 + 4 + 4 + 1 + 2 + TAG_LEN + MAC_LEN)
    zone_id, epoch, flag, count = struct.unpack_from(">IIBH", body, 4)
    offset = 15
    locals_ = []
    for _ in range(count):
        if offset + 2 > len(body) - TAG_LEN:
            raise ProtocolError("更新确认被截断")
        (local,) = struct.unpack_from(">H", body, offset)
        locals_.append(local)
        offset += 2
    if offset + TAG_LEN != len(body):
        raise ProtocolError("更新确认长度不匹配")
    if flag not in (FLAG_MISSING, FLAG_PRESENT):
        raise ProtocolError("差额帧种类不合法")
    return ZoneReport("partial", zone_id, epoch, count, flag, tuple(locals_), body[offset:], body, mac)


def parse_detail(token: bytes) -> ZoneDetail:
    if not token.startswith(ZDET):
        raise ProtocolError("更新确认格式错误")
    body, mac = _split_mac(token, 4 + 4 + 4 + 2 + MAC_LEN)
    zone_id, epoch, count = struct.unpack_from(">IIH", body, 4)
    offset = 14
    items = []
    for _ in range(count):
        if offset + 2 + TAG_LEN > len(body):
            raise ProtocolError("更新确认被截断")
        (local,) = struct.unpack_from(">H", body, offset)
        tag = body[offset + 2:offset + 2 + TAG_LEN]
        items.append((local, tag))
        offset += 2 + TAG_LEN
    if offset != len(body):
        raise ProtocolError("更新确认长度不匹配")
    return ZoneDetail(zone_id, epoch, tuple(items), body, mac)
