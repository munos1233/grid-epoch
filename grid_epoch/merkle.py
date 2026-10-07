"""稀疏 Merkle 吊销树。空子树按层共享哈希，省级只沿着被吊销叶子向上计算。"""

from __future__ import annotations

import bisect

from .crypto import sm3


_EMPTY_LEAF = sm3(b"EMP1")
_REVOKED_LEAF = sm3(b"REV1")


class RevocationTree:
    def __init__(self, n_leaves: int, revoked: set[int]) -> None:
        if n_leaves < 2 or n_leaves & (n_leaves - 1):
            raise ValueError("树容量必须是不小于 2 的 2 的幂")
        self.n = n_leaves
        self.height = n_leaves.bit_length() - 1
        self.revoked = set(revoked)
        self._sorted = sorted(self.revoked)
        self._empty = [_EMPTY_LEAF]
        for _ in range(self.height):
            self._empty.append(sm3(self._empty[-1] + self._empty[-1]))
        self._memo: dict[tuple[int, int], bytes] = {}

    def root(self) -> bytes:
        return self._node(self.height, 0)

    def proof(self, leaf: int) -> tuple[bytes, ...]:
        if not 0 <= leaf < self.n:
            raise ValueError("叶子越界")
        siblings = []
        index = leaf
        for level in range(self.height):
            siblings.append(self._node(level, index ^ 1))
            index //= 2
        return tuple(siblings)

    def _covers(self, level: int, index: int) -> bool:
        span = 1 << level
        start = index * span
        pos = bisect.bisect_left(self._sorted, start)
        return pos < len(self._sorted) and self._sorted[pos] < start + span

    def _node(self, level: int, index: int) -> bytes:
        key = (level, index)
        cached = self._memo.get(key)
        if cached is not None:
            return cached
        if not self._covers(level, index):
            digest = self._empty[level]
        elif level == 0:
            digest = _REVOKED_LEAF
        else:
            digest = sm3(self._node(level - 1, index * 2) + self._node(level - 1, index * 2 + 1))
        self._memo[key] = digest
        return digest


def proof_status(n_leaves: int, root: bytes, leaf: int, siblings: tuple[bytes, ...] | list[bytes]) -> str | None:
    """返回 live、revoked；路径对不上根时返回 None。"""
    height = n_leaves.bit_length() - 1
    if n_leaves < 2 or n_leaves & (n_leaves - 1) or not 0 <= leaf < n_leaves or len(siblings) != height:
        return None
    for leaf_hash, status in ((_EMPTY_LEAF, "live"), (_REVOKED_LEAF, "revoked")):
        digest = leaf_hash
        index = leaf
        for sibling in siblings:
            if len(sibling) != 32:
                return None
            if index & 1:
                digest = sm3(sibling + digest)
            else:
                digest = sm3(digest + sibling)
            index //= 2
        if digest == root:
            return status
    return None
