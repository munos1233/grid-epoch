"""长期完全子树。叶子按台区区间单调分配，用过的槽位不再回收。"""

from __future__ import annotations

from .derive import as_node_key, descend_node
from .errors import ProtocolError
from .tree import cover_nodes, path_nodes


GATEWAY_SLOTS = 4


def default_span(n_leaves: int) -> int:
    """生产树 2^28 用 2048 槽。较小的容量树用 512。演示树用 8 或 4。"""
    if n_leaves >= (1 << 28):
        return 2048
    if n_leaves >= (1 << 20):
        return 512
    if n_leaves >= 16 and n_leaves % 8 == 0:
        zones = n_leaves // 8
        if zones >= 2 and zones & (zones - 1) == 0:
            return 8
    return 4


def batch_span(zone_span: int) -> int:
    """供货批次。2048 槽的台区是 64 叶。小树缩小，仍是 2 的幂，并且小于台区槽。"""
    if zone_span >= 2048:
        return 64
    if zone_span >= 512:
        return 16
    if zone_span >= 8:
        return 2
    return 1


def county_node(n_leaves: int, span: int, county_index: int) -> int:
    """县在地市广播树上的节点。覆盖连续的台区槽，本身是一棵对齐子树。"""
    zones = n_leaves // span
    width = county_zone_count(zones)
    if width < 1 or zones % width != 0:
        raise ValueError("县界没有对齐")
    county_leaves = width * span
    count = zones // width
    if not 0 <= county_index < count:
        raise ValueError("县界越界")
    depth = (n_leaves // county_leaves).bit_length() - 1
    return (1 << depth) + county_index


def county_index(slot: int, zone_slots: int) -> int:
    """县序号只看注册槽号，不看行政台区号。"""
    if zone_slots < 1 or not 0 <= slot < zone_slots:
        raise ValueError("县槽越界")
    return slot // county_zone_count(zone_slots)


def county_zone_count(zone_slots: int) -> int:
    """县占连续台区槽。生产规模是 256。小树取一半以内最大的 2 的幂。"""
    if zone_slots >= 512:
        return 256
    half = zone_slots // 2
    count = 1
    while count * 2 <= half:
        count *= 2
    return count


class Subtree:
    def __init__(self, n_leaves: int, master: bytes, label: bytes, span: int = 1) -> None:
        if n_leaves < 2 or n_leaves & (n_leaves - 1):
            raise ValueError("树容量必须是不小于 2 的 2 的幂")
        if span < 1 or n_leaves % span != 0:
            raise ValueError("区间宽度必须整除树容量")
        zones = n_leaves // span
        if zones < 1 or zones & (zones - 1):
            raise ValueError("台区个数必须是 2 的幂")
        self.n = n_leaves
        self.master = as_node_key(master)
        self.label = label
        self.span = span
        self.batch = batch_span(span)
        self.revoked: set[int] = set()
        self._cursor: dict[int, int] = {}

    def node_key(self, node_id: int) -> bytes:
        return descend_node(self.master, node_id)

    def path_material(self, leaf: int) -> tuple[list[int], dict[int, bytes]]:
        order = path_nodes(leaf, self.n)
        return order, {node_id: self.node_key(node_id) for node_id in order}

    def cover(self) -> list[int]:
        return cover_nodes(self.n, self.revoked)

    def allocate(self, zone_index: int) -> int:
        start, end = self._span_bounds(zone_index)
        cursor = self._cursor.get(zone_index, start)
        while cursor < end and cursor in self.revoked:
            cursor += 1
        if cursor >= end:
            raise ProtocolError("台区槽位已用尽")
        self._cursor[zone_index] = cursor + 1
        return cursor

    def revoke_span(self, zone_index: int) -> None:
        """整段标进吊销集，包括还没分配的槽位。被摘掉的是这一个台区节点。"""
        start, end = self._span_bounds(zone_index)
        self.revoked.update(range(start, end))
        self._cursor[zone_index] = end

    def revoke_batch(self, zone_index: int, batch_index: int) -> None:
        start, _end = self._span_bounds(zone_index)
        count = self.span // self.batch
        if not 0 <= batch_index < count:
            raise ProtocolError("批次越界")
        origin = start + batch_index * self.batch
        self.revoked.update(range(origin, origin + self.batch))

    def revoke_county(self, county_index: int) -> None:
        zones = self.n // self.span
        width = county_zone_count(zones)
        if width < 1 or zones % width != 0:
            raise ProtocolError("县界没有对齐")
        start = county_index * width
        if county_index < 0 or start + width > zones:
            raise ProtocolError("县界越界")
        for zone_index in range(start, start + width):
            self.revoke_span(zone_index)

    def bitmap(self) -> bytes:
        raw = bytearray((self.n + 7) // 8)
        for leaf in self.revoked:
            raw[leaf >> 3] |= 1 << (leaf & 7)
        return bytes(raw)

    def _span_bounds(self, zone_index: int) -> tuple[int, int]:
        if zone_index < 0:
            raise ProtocolError("台区区间越界")
        start = zone_index * self.span
        end = start + self.span
        if end > self.n:
            raise ProtocolError("台区区间越界")
        return start, end

    @staticmethod
    def bit_set(bits: bytes, leaf: int) -> bool:
        if leaf < 0 or (leaf >> 3) >= len(bits):
            return True
        return bool(bits[leaf >> 3] & (1 << (leaf & 7)))
