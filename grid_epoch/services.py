"""终端上行。GE01 是电能量，GE03 是控制。不解析 DL/T 帧。

DL/T 645 的读电能、读冻结，以及 DL/T 698.45 的 GET、电能 REPORT，用 GE01 业务密钥。
DL/T 645 的跳闸、合闸、对时、写参，以及 DL/T 698.45 的 ACTION、设时钟，用 GE03 控制密钥。
"""

from __future__ import annotations

import struct

from .aead import open_aead, seal
from .crypto import hmac_sm3
from .errors import AuthFailed, ProtocolError


GE01 = b"GE01"
GE03 = b"GE03"

# 规约操作名只作对应，不解析报文。
DLT645_BUSINESS = ("读电能", "读冻结")
DLT645_CONTROL = ("跳闸", "合闸", "对时", "写参")
DLT698_BUSINESS = ("GET", "REPORT")
DLT698_CONTROL = ("ACTION", "设时钟")

_SERVICE = {
    ("645", name): GE01 for name in DLT645_BUSINESS
} | {
    ("645", name): GE03 for name in DLT645_CONTROL
} | {
    ("698.45", name): GE01 for name in DLT698_BUSINESS
} | {
    ("698.45", name): GE03 for name in DLT698_CONTROL
}


def service_for(standard: str, operation: str) -> bytes:
    try:
        return _SERVICE[(standard, operation)]
    except KeyError as exc:
        raise ProtocolError("服务号不合法") from exc


def seal_record(service: bytes, tid: int, epoch: int, counter: int, aead_key: bytes, mac_key: bytes, plaintext: bytes) -> bytes:
    if service not in (GE01, GE03):
        raise ProtocolError("服务号不合法")
    if not 0 < counter <= 0xFFFFFFFF:
        raise ProtocolError("上行序号不合法")
    sealed = seal(aead_key, plaintext)
    head = service + struct.pack(">QII", tid, epoch, counter)
    mac = hmac_sm3(mac_key, head + sealed)
    return head + sealed + mac


def parse_record(record: bytes):
    if len(record) < 20 + 18 + 32 or record[:4] not in (GE01, GE03):
        raise ProtocolError("终端业务报文格式错误")
    service = record[:4]
    tid, epoch, counter = struct.unpack_from(">QII", record, 4)
    ct_len = struct.unpack_from(">H", record, 20 + 16)[0]
    sealed_len = 18 + ct_len + 32
    end = 20 + sealed_len
    if end + 32 != len(record):
        raise ProtocolError("终端业务报文长度不匹配")
    sealed = record[20:end]
    mac = record[end:]
    return service, tid, epoch, counter, sealed, mac, record[:end]


def open_record(record: bytes, mac_key: bytes, aead_key: bytes) -> tuple[bytes, int, int, int, bytes]:
    service, tid, epoch, counter, sealed, mac, mac_body = parse_record(record)
    import hmac

    if not hmac.compare_digest(hmac_sm3(mac_key, mac_body), mac):
        raise AuthFailed("终端认证失败")
    return service, tid, epoch, counter, open_aead(aead_key, sealed)


def accept_counter(last: int, counter: int) -> None:
    if counter <= last:
        raise AuthFailed("上行序号拒绝")
