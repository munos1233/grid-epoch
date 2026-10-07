"""逻辑密钥树。无吊销时覆盖集只有根节点，广播报文与终端规模无关。"""

from __future__ import annotations


def covers_node(ancestor: int, node_id: int) -> bool:
    """ancestor 是 node_id 自己，或是它走到根之前的祖先。"""
    if ancestor < 1 or node_id < 1:
        return False
    current = node_id
    while current > ancestor:
        current //= 2
    return current == ancestor


def path_nodes(leaf_index: int, n: int) -> list[int]:
    if n < 2 or n & (n - 1):
        raise ValueError("更新簇容量必须是不小于 2 的 2 的幂")
    if not 0 <= leaf_index < n:
        raise ValueError("叶子越界")
    node = n + leaf_index
    nodes = []
    while node >= 1:
        nodes.append(node)
        node //= 2
    return nodes


def cover_nodes(n: int, revoked_leaves: set[int]) -> list[int]:
    """返回恰好覆盖未吊销叶子的最小节点集。"""
    if n < 2 or n & (n - 1):
        raise ValueError("更新簇容量必须是不小于 2 的 2 的幂")
    if not revoked_leaves:
        return [1]
    dirty: set[int] = set()
    for leaf in revoked_leaves:
        if not 0 <= leaf < n:
            raise ValueError("吊销叶子越界")
        node = n + leaf
        while node >= 1 and node not in dirty:
            dirty.add(node)
            node //= 2
    if 1 not in dirty:
        return [1]
    cover = []
    limit = 2 * n
    for node in dirty:
        for child in (node * 2, node * 2 + 1):
            if child < limit and child not in dirty:
                cover.append(child)
    cover.sort()
    return cover


def subtree_leaf_range(n: int, node_id: int) -> tuple[int, int]:
    """节点覆盖的叶子区间，左闭右开。内部节点只能圈定整棵子树。"""
    if n < 2 or n & (n - 1):
        raise ValueError("更新簇容量必须是不小于 2 的 2 的幂")
    if not 1 <= node_id < 2 * n:
        raise ValueError("节点号越界")
    depth = node_id.bit_length() - 1
    span = n >> depth
    start = (node_id - (1 << depth)) * span
    return start, start + span
