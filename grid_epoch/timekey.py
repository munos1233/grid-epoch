"""业务种子的时间树。主站保留根，能重算任意纪元；终端快进后删掉能推出过去的节点。

每 65536 个纪元为一代。进入一代的最后一个纪元时，用该叶子单向推出下一代的根。
日更约 180 年才换一次代；换代之后协议不在 65536 处停住。
"""

from __future__ import annotations

from .crypto import kdf
from .errors import EpochRejected


HEIGHT = 16
ERA = 1 << HEIGHT


def time_child(parent: bytes, bit: int, depth: int) -> bytes:
    label = b"FSL0" if bit == 0 else b"FSR1"
    return kdf(bytes(parent) + label + bytes((depth,)), 32)


def next_era_root(last_leaf: bytes) -> bytes:
    return kdf(bytes(last_leaf) + b"NEXT", 32)


def _walk(root: bytes, epoch_in_era: int) -> bytes:
    if not 1 <= epoch_in_era <= ERA:
        raise EpochRejected("纪元超出时间树")
    index = epoch_in_era - 1
    node = root
    for depth in range(HEIGHT):
        bit = (index >> (HEIGHT - 1 - depth)) & 1
        node = time_child(node, bit, depth)
    return node


def time_leaf(root: bytes, epoch: int) -> bytes:
    if epoch < 1:
        raise EpochRejected("纪元超出时间树")
    era = (epoch - 1) // ERA
    local = (epoch - 1) % ERA + 1
    node = root
    for _ in range(era):
        node = next_era_root(_walk(node, ERA))
    return _walk(node, local)


class TimeFrontier:
    """保存能推出当前纪元和未来纪元的节点。过去的节点在快进时抹掉。"""

    def __init__(self, root: bytes) -> None:
        self.era = 0
        self.nodes: list[tuple[int, int, bytearray]] = [(0, HEIGHT, bytearray(root))]
        self.index: int | None = None

    def advance_epoch(self, epoch: int) -> bytes:
        if epoch < 1:
            raise EpochRejected("纪元超出时间树")
        target_era = (epoch - 1) // ERA
        local = (epoch - 1) % ERA
        if target_era < self.era:
            raise EpochRejected("业务种子不能退回已删除的纪元")
        while self.era < target_era:
            last = self._advance(ERA - 1)
            nxt = next_era_root(last)
            for _start, _span, key in self.nodes:
                _wipe(key)
            self.nodes = [(0, HEIGHT, bytearray(nxt))]
            self.index = None
            self.era += 1
        return self._advance(local)

    def wipe(self) -> None:
        for _start, _span, key in self.nodes:
            _wipe(key)
        self.nodes.clear()
        self.index = None

    def current_leaf(self) -> bytes:
        if self.index is None:
            raise EpochRejected("业务种子还停在灌装根上")
        for start, span_log, key in self.nodes:
            if start == self.index and span_log == 0:
                return bytes(key)
        raise EpochRejected("时间树前沿里没有当前纪元")

    def covers(self, epoch: int) -> bool:
        if epoch < 1:
            return False
        era = (epoch - 1) // ERA
        if era != self.era:
            return False
        index = (epoch - 1) % ERA
        for start, span_log, _key in self.nodes:
            if start <= index < start + (1 << span_log):
                return True
        return False

    def _advance(self, index: int) -> bytes:
        if self.index is not None and index < self.index:
            raise EpochRejected("业务种子不能退回已删除的纪元")
        if self.index == index:
            return self.current_leaf()
        kept: list[tuple[int, int, bytearray]] = []
        for start, span_log, key in self.nodes:
            span = 1 << span_log
            if start + span <= index:
                _wipe(key)
                continue
            if start > index:
                kept.append((start, span_log, key))
                continue
            kept.extend(_split_past(start, span_log, key, index))
            _wipe(key)
        self.nodes = sorted(kept, key=lambda item: item[0])
        self.index = index
        return self.current_leaf()


def _split_past(start: int, span_log: int, key: bytes, target: int) -> list[tuple[int, int, bytearray]]:
    kept: list[tuple[int, int, bytearray]] = []
    while span_log > 0:
        depth = HEIGHT - span_log
        left = time_child(key, 0, depth)
        right = time_child(key, 1, depth)
        mid = start + (1 << (span_log - 1))
        if target < mid:
            kept.append((mid, span_log - 1, bytearray(right)))
            start, span_log, key = start, span_log - 1, left
        else:
            start, span_log, key = mid, span_log - 1, right
    kept.append((start, 0, bytearray(key)))
    return kept


def _wipe(key: bytearray) -> None:
    for i in range(len(key)):
        key[i] = 0
