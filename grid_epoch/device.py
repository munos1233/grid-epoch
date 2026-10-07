"""终端自己生成 SM2 密钥。地市用公钥做 C1C3C2 封装，私钥只留在终端。"""

from __future__ import annotations

import secrets
import struct

from gmssl import sm2
from gmssl import sm3 as gm_sm3

from .crypto import sm3
from .errors import ProtocolError


_MAGIC = b"GEPR"
_IDENTITY = b"GES9"


class DeviceKey:
    def __init__(self, private_key: str | None = None) -> None:
        table = sm2.default_ecc_table
        order = int(table["n"], 16)
        if private_key is None:
            secret = secrets.randbelow(order - 1) + 1
            private_key = f"{secret:064x}"
        self._private = private_key
        helper = sm2.CryptSM2(public_key="00" * 64, private_key=private_key, mode=1)
        self.public_key = helper._kg(int(private_key, 16), table["g"])
        self._crypt = sm2.CryptSM2(public_key=self.public_key, private_key=private_key, mode=1)

    def discard(self) -> None:
        self._private = ""
        self._crypt = None

    def decrypt(self, blob: bytes) -> bytes:
        if self._crypt is None:
            raise ProtocolError("终端已销毁")
        opened = self._crypt.decrypt(blob)
        if not opened:
            raise ProtocolError("灌装包解不开")
        return opened


def _sm2_encrypt(public_key: str, plain: bytes) -> bytes | None:
    """C1C3C2，和 gmssl mode=1 的解密布局一致。标量取在曲线阶以内，组不出点就换一个。"""
    crypt = sm2.CryptSM2(public_key=public_key, private_key="00" * 32, mode=1)
    order = int(crypt.ecc_table["n"], 16)
    msg = plain.hex()
    width = len(msg)
    for _ in range(64):
        k = secrets.randbelow(order - 1) + 1
        try:
            c1 = crypt._kg(k, crypt.ecc_table["g"])
            xy = crypt._kg(k, public_key)
            if not c1 or not xy or len(xy) != crypt.para_len * 2:
                continue
            x2 = xy[: crypt.para_len]
            y2 = xy[crypt.para_len :]
            derived = gm_sm3.sm3_kdf(xy.encode("utf8"), width / 2)
            if not derived or int(derived, 16) == 0:
                continue
            form = "%%0%dx" % width
            c2 = form % (int(msg, 16) ^ int(derived, 16))
            c3 = gm_sm3.sm3_hash(list(bytes.fromhex(x2 + msg + y2)))
            blob = bytes.fromhex(c1 + c3 + c2)
        except Exception:
            continue
        if len(blob) == 64 + 32 + len(plain):
            return blob
    return None


def _seal(public_key: str, magic: bytes, payload: bytes) -> bytes:
    body = magic + payload
    plain = body + sm3(body)
    blob = _sm2_encrypt(public_key, plain)
    if blob is None:
        raise ProtocolError("灌装封装失败")
    return blob


def _open(device: DeviceKey, blob: bytes, magic: bytes) -> bytes:
    try:
        plain = device.decrypt(blob)
    except ProtocolError:
        raise
    except Exception as exc:
        raise ProtocolError("灌装包解不开") from exc
    if len(plain) < 4 + 32 or plain[:4] != magic:
        raise ProtocolError("灌装包解不开")
    body, mac = plain[:-32], plain[-32:]
    if sm3(body) != mac:
        raise ProtocolError("灌装包解不开")
    return body[4:]


def seal_provision(public_key: str, payload: bytes) -> bytes:
    return _seal(public_key, _MAGIC, payload)


def open_provision(device: DeviceKey, blob: bytes) -> bytes:
    return _open(device, blob, _MAGIC)


def seal_identity(public_key: str, sm9_user: bytes, sm9_public: bytes) -> bytes:
    """省级把 SM9 用户私钥封给设备公钥。地市看不到这份明文。"""
    payload = struct.pack(">I", len(sm9_user)) + sm9_user + struct.pack(">I", len(sm9_public)) + sm9_public
    return _seal(public_key, _IDENTITY, payload)


def open_identity(device: DeviceKey, blob: bytes) -> tuple[bytes, bytes]:
    payload = _open(device, blob, _IDENTITY)
    if len(payload) < 8:
        raise ProtocolError("灌装包解不开")
    (user_len,) = struct.unpack_from(">I", payload, 0)
    if 4 + user_len + 4 > len(payload):
        raise ProtocolError("灌装包解不开")
    user = payload[4:4 + user_len]
    offset = 4 + user_len
    (pub_len,) = struct.unpack_from(">I", payload, offset)
    offset += 4
    if offset + pub_len != len(payload) or not user:
        raise ProtocolError("灌装包解不开")
    return user, payload[offset:offset + pub_len]


def pack_material(
    seed_mgmt: bytes,
    seed_biz: bytes,
    sd_secret: bytes,
    sm9_user: bytes,
    sm9_public: bytes,
    path_order: list[int],
    path_keys: dict[int, bytes],
    sd_stubs: dict[tuple[int, int], bytes],
    full_bases: dict[int, bytes],
) -> bytes:
    buf = bytearray()
    for item in (seed_mgmt, seed_biz, sd_secret, sm9_user, sm9_public):
        buf += struct.pack(">I", len(item)) + item
    buf += struct.pack(">H", len(path_order))
    for node in path_order:
        key = path_keys[node]
        buf += struct.pack(">IH", node, len(key)) + key
    buf += struct.pack(">H", len(sd_stubs))
    for (root, hanging), key in sd_stubs.items():
        buf += struct.pack(">IIH", root, hanging, len(key)) + key
    buf += struct.pack(">H", len(full_bases))
    for node, key in full_bases.items():
        buf += struct.pack(">IH", node, len(key)) + key
    return bytes(buf)


def unpack_material(payload: bytes) -> dict:
    offset = 0

    def take() -> bytes:
        nonlocal offset
        if offset + 4 > len(payload):
            raise ProtocolError("灌装材料被截断")
        (length,) = struct.unpack_from(">I", payload, offset)
        offset += 4
        if offset + length > len(payload):
            raise ProtocolError("灌装材料被截断")
        chunk = payload[offset:offset + length]
        offset += length
        return chunk

    seed_mgmt, seed_biz, sd_secret, sm9_user, sm9_public = (take() for _ in range(5))
    if offset + 2 > len(payload):
        raise ProtocolError("灌装材料被截断")
    (path_count,) = struct.unpack_from(">H", payload, offset)
    offset += 2
    path_order = []
    path_keys = {}
    for _ in range(path_count):
        if offset + 6 > len(payload):
            raise ProtocolError("灌装材料被截断")
        node, key_len = struct.unpack_from(">IH", payload, offset)
        offset += 6
        path_order.append(node)
        path_keys[node] = payload[offset:offset + key_len]
        offset += key_len
    if offset + 2 > len(payload):
        raise ProtocolError("灌装材料被截断")
    (stub_count,) = struct.unpack_from(">H", payload, offset)
    offset += 2
    stubs = {}
    for _ in range(stub_count):
        if offset + 10 > len(payload):
            raise ProtocolError("灌装材料被截断")
        root, hanging, key_len = struct.unpack_from(">IIH", payload, offset)
        offset += 10
        stubs[(root, hanging)] = payload[offset:offset + key_len]
        offset += key_len
    if offset + 2 > len(payload):
        raise ProtocolError("灌装材料被截断")
    (base_count,) = struct.unpack_from(">H", payload, offset)
    offset += 2
    bases = {}
    for _ in range(base_count):
        if offset + 6 > len(payload):
            raise ProtocolError("灌装材料被截断")
        node, key_len = struct.unpack_from(">IH", payload, offset)
        offset += 6
        bases[node] = payload[offset:offset + key_len]
        offset += key_len
    if offset != len(payload):
        raise ProtocolError("灌装材料长度不匹配")
    return {
        "seed_mgmt": seed_mgmt,
        "seed_biz": seed_biz,
        "sd_secret": sd_secret,
        "sm9_user": sm9_user or None,
        "sm9_public": sm9_public or None,
        "path_order": path_order,
        "path_keys": path_keys,
        "sd_stubs": stubs,
        "full_bases": bases,
    }
