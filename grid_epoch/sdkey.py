"""子集差标签。从树主密钥单独派生，不经过完全子树的 NODE 路径密钥。

节点标签是 KDF(master ‖ "SDLB" ‖ 节点号 ‖ 代数)。代数保持 0，沿子树用 SDL0 / SDR1
单向走到悬挂点。子集密钥再混入 SDEP 代数秘密。叶子不再轮换，这份秘密也不再递增。
"""

from __future__ import annotations

import struct

from .crypto import kdf
from .tree import path_nodes


def node_label(master: bytes, node_id: int, generation: int) -> bytes:
    return kdf(master + b"SDLB" + struct.pack(">II", node_id, generation), 32)


def epoch_secret(master: bytes, generation: int) -> bytes:
    return kdf(master + b"SDEP" + struct.pack(">I", generation), 32)


def _step(label: bytes, bit: int, depth: int) -> bytes:
    tag = b"SDL0" if bit == 0 else b"SDR1"
    return kdf(label + tag + bytes([depth]), 32)


def continue_walk(label: bytes, start: int, target: int) -> bytes:
    if start == target:
        return label
    chain = []
    node = target
    while node != start:
        if node < 1:
            raise ValueError("排除节点不在子树内")
        chain.append(node)
        node //= 2
    chain.reverse()
    depth = start.bit_length() - 1
    for node in chain:
        depth += 1
        label = _step(label, node & 1, depth)
    return label


def walk_label(master: bytes, root: int, target: int, generation: int = 0) -> bytes:
    return continue_walk(node_label(master, root, generation), root, target)


def full_base(master: bytes, node_id: int) -> bytes:
    return kdf(node_label(master, node_id, 0) + b"SFUL", 16)


def subset_key(label: bytes, secret: bytes) -> bytes:
    return kdf(label + b"SKEY" + secret, 16)


def full_key(base: bytes, secret: bytes) -> bytes:
    return kdf(b"SFIN" + base + secret, 16)


def cover_subset_key(master: bytes, secret: bytes, root: int, excluded: int) -> bytes:
    if excluded == 0:
        return full_key(full_base(master, root), secret)
    return subset_key(walk_label(master, root, excluded, 0), secret)


def stubs_for_leaf(n: int, leaf: int, master: bytes) -> dict[tuple[int, int], bytes]:
    leaf_node = n + leaf
    stubs: dict[tuple[int, int], bytes] = {}
    node = leaf_node
    while node > 1:
        parent = node // 2
        sibling = node ^ 1
        ancestor = parent
        while True:
            stubs[(ancestor, sibling)] = walk_label(master, ancestor, sibling, 0)
            if ancestor == 1:
                break
            ancestor //= 2
        node = parent
    return stubs


def full_bases_for_leaf(n: int, leaf: int, master: bytes) -> dict[int, bytes]:
    return {node_id: full_base(master, node_id) for node_id in path_nodes(leaf, n)}


def _is_ancestor(ancestor: int, node: int) -> bool:
    current = node
    while current > ancestor:
        current //= 2
    return current == ancestor


def derive_open_key(
    stubs: dict[tuple[int, int], bytes],
    bases: dict[int, bytes],
    secret: bytes,
    root: int,
    excluded: int,
) -> bytes | None:
    if excluded == 0:
        base = bases.get(root)
        if base is None:
            return None
        return full_key(base, secret)
    chosen: tuple[int, bytes] | None = None
    for (stub_root, hanging), label in stubs.items():
        if stub_root != root:
            continue
        if hanging != excluded and not _is_ancestor(hanging, excluded):
            continue
        if chosen is None or hanging.bit_length() > chosen[0].bit_length():
            chosen = (hanging, label)
    if chosen is None:
        return None
    hanging, label = chosen
    return subset_key(continue_walk(label, hanging, excluded), secret)


def allowed_node(node_id: int, cover_node: int) -> bool:
    """覆盖节点下的成员都持有 node_id，当且仅当 node_id 在到该覆盖节点的路径上。"""
    return _is_ancestor(node_id, cover_node)
