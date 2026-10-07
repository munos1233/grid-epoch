"""纪元广播。SM2 只签带头，终端只收一条覆盖条目和兄弟哈希。"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .crypto import sm3


TERMINAL_MAGIC = b"GEUP"
GATEWAY_MAGIC = b"GEGW"
REVOCATION_MAGIC = b"GERV"

ALG_SM2 = 1

_TERMINAL_VERSION = 5
_GATEWAY_VERSION = 4
_REVOCATION_VERSION = 1
COVER_CS = 1
COVER_SD = 2
_EMPTY_ENTRY = sm3(b"EMP2")
_TERMINAL_HEADER = 68
_GATEWAY_HEADER = 64


@dataclass(frozen=True)
class EntryPackage:
    kind: str
    area: int
    cohort_id: int
    epoch: int
    timestamp: int
    rev_version: int
    cover: str
    entries: dict
    order: tuple
    canonical: dict
    proof: tuple[bytes, ...] | None
    slice_index: int | None
    merkle_root: bytes
    signatures: tuple[tuple[int, bytes], ...]
    raw_body: bytes
    zone_hint: int = 0

    def sm2_signature(self) -> bytes:
        return _require_alg(self.signatures, ALG_SM2)


@dataclass(frozen=True)
class RevocationPackage:
    area: int
    cohort_id: int
    rev_version: int
    root: bytes
    signatures: tuple[tuple[int, bytes], ...]
    raw_body: bytes

    def sm2_signature(self) -> bytes:
        return _require_alg(self.signatures, ALG_SM2)


def _require_alg(signatures: tuple[tuple[int, bytes], ...], alg: int) -> bytes:
    for item_alg, sig in signatures:
        if item_alg == alg:
            return sig
    raise ValueError("缺少所需签名")


def _canonical(cover: int, item) -> bytes:
    if cover == COVER_CS:
        node_id, sealed = item
        return struct.pack(">IH", node_id, len(sealed)) + sealed
    if cover != COVER_SD:
        raise ValueError("覆盖种类不合法")
    root, excluded, sealed = item
    return struct.pack(">IIH", root, excluded, len(sealed)) + sealed


def _ordered(cover: int, entries: list) -> list:
    if cover == COVER_CS:
        return sorted(entries, key=lambda item: item[0])
    if cover != COVER_SD:
        raise ValueError("覆盖种类不合法")
    return sorted(entries, key=lambda item: (item[0], item[1]))


def _pack_entries(cover: int, entries: list) -> bytes:
    buf = bytearray(struct.pack(">H", len(entries)))
    for item in entries:
        buf += _canonical(cover, item)
    return bytes(buf)


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    root, _proofs = _merkle(leaf_hashes)
    return root


def _merkle(leaf_hashes: list[bytes]) -> tuple[bytes, list[tuple[bytes, ...]]]:
    if not leaf_hashes:
        raise ValueError("覆盖条目为空")
    level = list(leaf_hashes)
    while level and (len(level) & (len(level) - 1)):
        level.append(_EMPTY_ENTRY)
    proofs: list[list[bytes]] = [[] for _ in leaf_hashes]
    indexes = list(range(len(level)))
    while len(level) > 1:
        for position, index in enumerate(indexes[: len(leaf_hashes)]):
            if position >= len(proofs):
                break
            proofs[position].append(level[index ^ 1])
        nxt = []
        for index in range(0, len(level), 2):
            nxt.append(sm3(level[index] + level[index + 1]))
        level = nxt
        indexes = [index // 2 for index in indexes]
    return level[0], [tuple(item) for item in proofs]


def merkle_check(leaf_hash: bytes, index: int, proof: tuple[bytes, ...], root: bytes) -> bool:
    digest = leaf_hash
    cursor = index
    for sibling in proof:
        if len(sibling) != 32:
            return False
        if cursor & 1:
            digest = sm3(sibling + digest)
        else:
            digest = sm3(digest + sibling)
        cursor //= 2
    return digest == root


def _entry_key(cover: int, item):
    if cover == COVER_CS:
        return item[0]
    return (item[0], item[1])


def build_terminal_package(
    area: int,
    zone_hint: int,
    cohort_id: int,
    epoch: int,
    timestamp: int,
    rev_version: int,
    cover: int,
    entries: list,
    sign,
) -> bytes:
    return _build(
        TERMINAL_MAGIC,
        _TERMINAL_VERSION,
        True,
        area,
        zone_hint,
        cohort_id,
        epoch,
        timestamp,
        rev_version,
        cover,
        entries,
        sign,
    )


def build_gateway_package(
    area: int,
    cohort_id: int,
    epoch: int,
    timestamp: int,
    rev_version: int,
    cover: int,
    entries: list,
    sign,
) -> bytes:
    return _build(
        GATEWAY_MAGIC,
        _GATEWAY_VERSION,
        False,
        area,
        0,
        cohort_id,
        epoch,
        timestamp,
        rev_version,
        cover,
        entries,
        sign,
    )


def _build(
    magic: bytes,
    version: int,
    with_zone: bool,
    area: int,
    zone_hint: int,
    cohort_id: int,
    epoch: int,
    timestamp: int,
    rev_version: int,
    cover: int,
    entries: list,
    sign,
) -> bytes:
    ordered = _ordered(cover, entries)
    hashes = [sm3(_canonical(cover, item)) for item in ordered]
    root = merkle_root(hashes)
    if with_zone:
        header = magic + struct.pack(
            ">BIIIIQIBH",
            version,
            area,
            zone_hint,
            cohort_id,
            epoch,
            timestamp,
            rev_version,
            cover,
            len(ordered),
        ) + root
    else:
        header = magic + struct.pack(
            ">BIIIQIBH",
            version,
            area,
            cohort_id,
            epoch,
            timestamp,
            rev_version,
            cover,
            len(ordered),
        ) + root
    payload = b"\x00" + _pack_entries(cover, ordered)
    return _finish(header, payload, sign)


def _finish(header: bytes, payload: bytes, sign) -> bytes:
    signed = sign(header)
    if isinstance(signed, bytes):
        signatures = [(ALG_SM2, signed)]
    else:
        signatures = list(signed)
    return header + struct.pack(">I", len(payload)) + payload + _pack_sigs(signatures)


def _pack_sigs(signatures: list[tuple[int, bytes]]) -> bytes:
    if not signatures or len(signatures) > 8:
        raise ValueError("签名套件数量不合法")
    seen = set()
    buf = bytearray()
    buf.append(len(signatures))
    for alg, sig in signatures:
        if alg in seen or not sig or len(sig) > 0xFFFF:
            raise ValueError("签名套件不合法")
        seen.add(alg)
        buf += struct.pack(">HH", alg, len(sig))
        buf += sig
    return bytes(buf)


def attach_signatures(body: bytes, signatures: list[tuple[int, bytes]]) -> bytes:
    return body + _pack_sigs(signatures)


def seal_signed(body: bytes, sign) -> bytes:
    """吊销根仍对整个报文体签名。纪元广播走带头签名。"""
    return _finish(body, b"", sign) if False else _seal_whole(body, sign)


def _seal_whole(body: bytes, sign) -> bytes:
    signed = sign(body)
    if isinstance(signed, bytes):
        signatures = [(ALG_SM2, signed)]
    else:
        signatures = list(signed)
    return body + _pack_sigs(signatures)


def _split_signatures(blob: bytes, body_end: int) -> tuple[bytes, tuple[tuple[int, bytes], ...]]:
    if body_end >= len(blob):
        raise ValueError("报文被截断")
    count = blob[body_end]
    offset = body_end + 1
    if not 1 <= count <= 8:
        raise ValueError("签名套件数量不合法")
    signatures = []
    seen = set()
    for _ in range(count):
        if offset + 4 > len(blob):
            raise ValueError("报文被截断")
        alg, sig_len = struct.unpack_from(">HH", blob, offset)
        offset += 4
        if alg in seen or offset + sig_len > len(blob):
            raise ValueError("签名套件不合法")
        seen.add(alg)
        signatures.append((alg, blob[offset:offset + sig_len]))
        offset += sig_len
    if offset != len(blob):
        raise ValueError("签名长度不匹配")
    if count != 1 or seen != {ALG_SM2}:
        raise ValueError("签名套件必须只有 SM2")
    return blob[:body_end], tuple(signatures)


def _unpack_canonical(blob: bytes, offset: int, cover: int) -> tuple[object, bytes, int]:
    if cover == COVER_CS:
        if offset + 6 > len(blob):
            raise ValueError("报文被截断")
        node_id, sealed_len = struct.unpack_from(">IH", blob, offset)
        start = offset
        offset += 6
        key = node_id
    elif cover == COVER_SD:
        if offset + 10 > len(blob):
            raise ValueError("报文被截断")
        root, excluded, sealed_len = struct.unpack_from(">IIH", blob, offset)
        start = offset
        offset += 10
        key = (root, excluded)
    else:
        raise ValueError("覆盖种类不合法")
    if offset + sealed_len > len(blob):
        raise ValueError("报文被截断")
    offset += sealed_len
    return key, blob[start:offset], offset


def _parse_payload(payload: bytes, cover: int, entry_count: int) -> tuple[dict, tuple, dict, tuple[bytes, ...] | None, int | None]:
    if not payload:
        raise ValueError("报文被截断")
    kind = payload[0]
    if kind == 0:
        entries, order, canonical, offset = _parse_full(payload, 1, cover)
        if offset != len(payload) or len(order) != entry_count:
            raise ValueError("覆盖条目数量不匹配")
        return entries, order, canonical, None, None
    if kind != 1:
        raise ValueError("广播载荷种类不合法")
    if len(payload) < 1 + 2 + 4:
        raise ValueError("报文被截断")
    index = struct.unpack_from(">H", payload, 1)[0]
    canonical_len = struct.unpack_from(">I", payload, 3)[0]
    start = 7
    if start + canonical_len >= len(payload):
        raise ValueError("报文被截断")
    raw = payload[start:start + canonical_len]
    cursor = start + canonical_len
    proof_len = payload[cursor]
    cursor += 1
    if cursor + proof_len * 32 != len(payload):
        raise ValueError("Merkle 证明长度不匹配")
    proof = tuple(payload[cursor + i * 32:cursor + (i + 1) * 32] for i in range(proof_len))
    key, sealed_bytes, consumed = _unpack_canonical(raw, 0, cover)
    if consumed != len(raw):
        raise ValueError("覆盖条目长度不匹配")
    if index >= entry_count:
        raise ValueError("覆盖条目序号越界")
    return {key: _sealed_of(cover, raw)}, (key,), {key: raw}, proof, index


def _sealed_of(cover: int, raw: bytes) -> bytes:
    if cover == COVER_CS:
        sealed_len = struct.unpack_from(">H", raw, 4)[0]
        return raw[6:6 + sealed_len]
    sealed_len = struct.unpack_from(">H", raw, 8)[0]
    return raw[10:10 + sealed_len]


def _parse_full(payload: bytes, offset: int, cover: int) -> tuple[dict, tuple, dict, int]:
    if offset + 2 > len(payload):
        raise ValueError("报文被截断")
    (count,) = struct.unpack_from(">H", payload, offset)
    offset += 2
    entries: dict = {}
    order = []
    canonical = {}
    for _ in range(count):
        key, raw, offset = _unpack_canonical(payload, offset, cover)
        if key in entries:
            raise ValueError("覆盖节点重复")
        entries[key] = _sealed_of(cover, raw)
        order.append(key)
        canonical[key] = raw
    return entries, tuple(order), canonical, offset


def _take_payload(blob: bytes, header_len: int) -> tuple[bytes, int]:
    if header_len + 4 > len(blob):
        raise ValueError("报文被截断")
    (payload_len,) = struct.unpack_from(">I", blob, header_len)
    start = header_len + 4
    end = start + payload_len
    if end > len(blob):
        raise ValueError("报文被截断")
    return blob[start:end], end


def parse_terminal_package(blob: bytes) -> EntryPackage:
    if len(blob) < _TERMINAL_HEADER or blob[:4] != TERMINAL_MAGIC:
        raise ValueError("不是终端纪元报文")
    if blob[4] != _TERMINAL_VERSION:
        raise ValueError("不支持的终端报文版本")
    area, zone_hint, cohort_id, epoch, timestamp, rev_version, cover, count = struct.unpack_from(
        ">IIIIQIBH", blob, 5
    )
    root = blob[36:68]
    if len(root) != 32:
        raise ValueError("Merkle 根被截断")
    payload, payload_end = _take_payload(blob, _TERMINAL_HEADER)
    entries, order, canonical, proof, index = _parse_payload(payload, cover, count)
    _body, signatures = _split_signatures(blob, payload_end)
    return EntryPackage(
        kind="terminal",
        area=area,
        zone_hint=zone_hint,
        cohort_id=cohort_id,
        epoch=epoch,
        timestamp=timestamp,
        rev_version=rev_version,
        cover=_cover_name(cover),
        entries=entries,
        order=order,
        canonical=canonical,
        proof=proof,
        slice_index=index,
        merkle_root=root,
        signatures=signatures,
        raw_body=blob[:_TERMINAL_HEADER],
    )


def parse_gateway_package(blob: bytes) -> EntryPackage:
    if len(blob) < _GATEWAY_HEADER or blob[:4] != GATEWAY_MAGIC:
        raise ValueError("不是gateway报文")
    if blob[4] != _GATEWAY_VERSION:
        raise ValueError("不支持的报文版本")
    area, cohort_id, epoch, timestamp, rev_version, cover, count = struct.unpack_from(">IIIQIBH", blob, 5)
    root = blob[32:64]
    payload, payload_end = _take_payload(blob, _GATEWAY_HEADER)
    entries, order, canonical, proof, index = _parse_payload(payload, cover, count)
    _body, signatures = _split_signatures(blob, payload_end)
    return EntryPackage(
        kind="gateway",
        area=area,
        cohort_id=cohort_id,
        epoch=epoch,
        timestamp=timestamp,
        rev_version=rev_version,
        cover=_cover_name(cover),
        entries=entries,
        order=order,
        canonical=canonical,
        proof=proof,
        slice_index=index,
        merkle_root=root,
        signatures=signatures,
        raw_body=blob[:_GATEWAY_HEADER],
        zone_hint=0,
    )


def commitment_ok(package: EntryPackage) -> bool:
    if package.proof is not None:
        if package.slice_index is None or len(package.order) != 1:
            return False
        key = package.order[0]
        return merkle_check(sm3(package.canonical[key]), package.slice_index, package.proof, package.merkle_root)
    hashes = [sm3(package.canonical[key]) for key in package.order]
    return merkle_root(hashes) == package.merkle_root


def forward_zone(blob: bytes, n: int, start: int, end: int) -> list[bytes]:
    """集中器只转发叶子落在本台区的省级切片，不另建密钥树，也不打开明文。"""
    if blob[:4] == TERMINAL_MAGIC:
        package = parse_terminal_package(blob)
    else:
        package = parse_gateway_package(blob)
    if package.proof is not None:
        raise ValueError("切片不能再抽")
    seen: set[int] = set()
    forwarded: list[bytes] = []
    for leaf in range(start, end):
        index = _covering_index(n, leaf, package)
        if index is None or index in seen:
            continue
        seen.add(index)
        forwarded.append(extract_for_leaf(blob, n, leaf))
    return forwarded


def extract_for_leaf(blob: bytes, n: int, leaf: int) -> bytes:
    package = parse_terminal_package(blob) if blob[:4] == TERMINAL_MAGIC else parse_gateway_package(blob)
    if package.proof is not None:
        raise ValueError("切片不能再抽")
    if not commitment_ok(package):
        raise ValueError("Merkle 根不一致")
    index = _covering_index(n, leaf, package)
    if index is None:
        raise ValueError("没有覆盖该叶子的条目")
    key = package.order[index]
    raw = package.canonical[key]
    _root, proofs = _merkle([sm3(package.canonical[item]) for item in package.order])
    proof = proofs[index]
    payload = (
        b"\x01"
        + struct.pack(">HI", index, len(raw))
        + raw
        + bytes([len(proof)])
        + b"".join(proof)
    )
    suffix_at = len(package.raw_body) + 4 + _payload_len(blob, len(package.raw_body))
    return package.raw_body + struct.pack(">I", len(payload)) + payload + blob[suffix_at:]


def _payload_len(blob: bytes, header_len: int) -> int:
    return struct.unpack_from(">I", blob, header_len)[0]


def _covering_index(n: int, leaf: int, package: EntryPackage) -> int | None:
    from .subsetdiff import live_leaves
    from .tree import path_nodes

    if package.cover == "cs":
        path = set(path_nodes(leaf, n))
        for index, node in enumerate(package.order):
            if node in path:
                return index
        return None
    for index, subset in enumerate(package.order):
        if leaf in live_leaves(n, subset):
            return index
    return None


def _cover_name(cover: int) -> str:
    if cover == COVER_CS:
        return "cs"
    if cover == COVER_SD:
        return "sd"
    raise ValueError("覆盖种类不合法")


def encode_revocation_body(area: int, cohort_id: int, rev_version: int, root: bytes) -> bytes:
    if len(root) != 32:
        raise ValueError("吊销根必须是 32 字节")
    return (
        REVOCATION_MAGIC
        + struct.pack(">BIII", _REVOCATION_VERSION, area, cohort_id, rev_version)
        + root
    )


def parse_revocation_package(blob: bytes) -> RevocationPackage:
    if len(blob) < 5 or blob[:4] != REVOCATION_MAGIC:
        raise ValueError("不是吊销根")
    if blob[4] != _REVOCATION_VERSION:
        raise ValueError("不支持的吊销根版本")
    area, cohort_id, rev_version = struct.unpack_from(">III", blob, 5)
    root_at = 5 + 12
    if root_at + 32 > len(blob):
        raise ValueError("吊销根被截断")
    root = blob[root_at:root_at + 32]
    body, signatures = _split_signatures(blob, root_at + 32)
    return RevocationPackage(
        area=area,
        cohort_id=cohort_id,
        rev_version=rev_version,
        root=root,
        signatures=signatures,
        raw_body=body,
    )


def slice_bytes(entry_count: int, sealed_len: int = 70) -> int:
    """1000 条覆盖时，终端切片的字节数。签名按 64 字节 SM2 估算。"""
    if entry_count < 1:
        raise ValueError("条目数至少为 1")
    padded = 1
    while padded < entry_count:
        padded *= 2
    proof_len = 0 if padded == 1 else padded.bit_length() - 1
    canonical = 6 + sealed_len
    payload = 1 + 2 + 4 + canonical + 1 + proof_len * 32
    return _TERMINAL_HEADER + 4 + payload + 1 + 4 + 64
