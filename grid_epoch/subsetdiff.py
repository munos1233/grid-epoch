"""覆盖选择。空吊销用完全子树。完整行政节点收成一条子集差密文，散点坏表也用子集差。"""

from __future__ import annotations

from bisect import bisect_left

from .tree import cover_nodes, subtree_leaf_range


def cs_terminal_keys(n: int) -> int:
    return n.bit_length()


def sd_terminal_keys(n: int) -> int:
    levels = n.bit_length() - 1
    return levels * (levels + 1) // 2


def is_contiguous(revoked: set[int]) -> bool:
    if len(revoked) < 2:
        return False
    return max(revoked) - min(revoked) + 1 == len(revoked)


def covers_whole_blocks(n: int, revoked: set[int], grain: int) -> bool:
    """吊销叶子正好铺满若干个对齐区块。整批、整区、整县都满足。"""
    if grain < 1 or n % grain != 0:
        raise ValueError("批次宽度必须整除树容量")
    if not revoked:
        return True
    counts: dict[int, int] = {}
    for leaf in revoked:
        if not 0 <= leaf < n:
            raise ValueError("吊销叶子越界")
        block = leaf // grain
        counts[block] = counts.get(block, 0) + 1
    return all(count == grain for count in counts.values())


def cover_choice(n: int, revoked: set[int], grain: int) -> str:
    """空吊销是根上的一条完全子树密文。其余用子集差。

    吊销集若正好铺满若干个批次，子集差会把每个被摘掉的行政节点收成一条密文。
    """
    if grain < 1 or n % grain != 0:
        raise ValueError("批次宽度必须整除树容量")
    if not revoked:
        return "cs"
    return "sd"


def planned_cover(n: int, revoked: set[int], grain: int) -> tuple[str, list]:
    kind = cover_choice(n, revoked, grain)
    if kind == "sd":
        return kind, sd_cover(n, revoked)
    return kind, cover_nodes(n, revoked)


def sd_cover(n: int, revoked: set[int] | list[int]) -> list[tuple[int, int]]:
    """返回 (子树根, 被排除的后代)。排除号为 0 表示整棵子树都接收。"""
    if n < 2 or n & (n - 1):
        raise ValueError("更新簇容量必须是不小于 2 的 2 的幂")
    ordered = sorted(revoked)
    if ordered and (ordered[0] < 0 or ordered[-1] >= n):
        raise ValueError("吊销叶子越界")
    state = _cover_state(1, 0, n, ordered)
    if state is None:
        return []
    kind, payload = state
    if kind == "full":
        return [(payload, 0)]
    return _collapse(payload)


def live_leaves(n: int, subset: tuple[int, int]) -> set[int]:
    root, excluded = subset
    start, end = subtree_leaf_range(n, root)
    leaves = set(range(start, end))
    if excluded:
        cut_start, cut_end = subtree_leaf_range(n, excluded)
        if not start <= cut_start < cut_end <= end:
            raise ValueError("排除节点不在子树内")
        leaves.difference_update(range(cut_start, cut_end))
    return leaves


def _cover_state(node: int, start: int, span: int, revoked: list[int]):
    if not revoked:
        return ("full", node)
    if len(revoked) == span:
        return None
    half = span // 2
    mid = start + half
    split = bisect_left(revoked, mid)
    left_r = revoked[:split]
    right_r = revoked[split:]
    left = _child_state(node * 2, start, half, left_r)
    right = _child_state(node * 2 + 1, mid, half, right_r)
    return _merge(node, left, right)


def _child_state(node: int, start: int, span: int, revoked: list[int]):
    if not revoked:
        return ("full", node)
    if len(revoked) == span:
        return None
    return _cover_state(node, start, span, revoked)


def _merge(node: int, left, right):
    left_node = node * 2
    right_node = node * 2 + 1
    if left is None and right is None:
        return None
    if _full(left) and _full(right):
        return ("full", node)
    if left is None and _full(right):
        return ("sets", [(node, left_node)])
    if right is None and _full(left):
        return ("sets", [(node, right_node)])
    if left is None:
        return right
    if right is None:
        return left
    if _full(left) and _anchored(right, right_node):
        return ("sets", [(node, right[1][0][1])])
    if _full(right) and _anchored(left, left_node):
        return ("sets", [(node, left[1][0][1])])
    sets: list[tuple[int, int]] = []
    if _full(left):
        sets.append((node, right_node))
    elif left is not None:
        sets.extend(left[1])
    if _full(right):
        sets.append((node, left_node))
    elif right is not None:
        sets.extend(right[1])
    return ("sets", sets)


def _collapse(sets: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """把 (父, 子) 和 (子, 孙) 收成 (父, 孙)，避免同一段接收区被拆开。"""
    outgoing: dict[int, list[int]] = {}
    for root, excluded in sets:
        outgoing.setdefault(root, []).append(excluded)
    unique = {
        root: exclusions[0]
        for root, exclusions in outgoing.items()
        if len(exclusions) == 1 and exclusions[0] != 0
    }
    incoming: dict[int, int] = {}
    for nxt in unique.values():
        incoming[nxt] = incoming.get(nxt, 0) + 1
    collapsed = []
    for root, excluded in sets:
        if root in unique and unique[root] == excluded and incoming.get(root, 0) == 1:
            continue
        if root in unique and unique[root] == excluded:
            target = excluded
            guard = 0
            while incoming.get(target, 0) == 1 and target in unique and guard < 64:
                target = unique[target]
                guard += 1
            collapsed.append((root, target))
        else:
            collapsed.append((root, excluded))
    return collapsed


def _full(state) -> bool:
    return state is not None and state[0] == "full"


def _anchored(state, node: int) -> bool:
    return (
        state is not None
        and state[0] == "sets"
        and len(state[1]) == 1
        and state[1][0][0] == node
        and state[1][0][1] != 0
    )
