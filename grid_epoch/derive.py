"""三级密钥的派生规格。C 热路径与这里的字节布局必须一致。"""

from __future__ import annotations

import struct

from .crypto import hmac_sm3, kdf


def city_mgmt(mk_mgmt: bytes, cohort_id: int) -> bytes:
    return kdf(mk_mgmt + b"CITY" + struct.pack(">I", cohort_id), 32)


def cohort_master(mk_mgmt: bytes, cohort_id: int) -> bytes:
    """地市管控委托密钥。省级主密钥不出地市。"""
    return city_mgmt(mk_mgmt, cohort_id)


def city_biz(mk_biz: bytes, area: int, cohort_id: int) -> bytes:
    return kdf(mk_biz + b"CIBZ" + struct.pack(">II", area, cohort_id), 32)


def county_mgmt(city_mgmt_key: bytes, county_index: int) -> bytes:
    """县管控密钥。从地市向下派生，推不出地市，也推不出兄弟县。"""
    return kdf(city_mgmt_key + b"CNTY" + struct.pack(">I", county_index), 32)


def county_biz(city_biz_key: bytes, county_index: int) -> bytes:
    return kdf(city_biz_key + b"CNBZ" + struct.pack(">I", county_index), 32)


def zone_key(county_mgmt_key: bytes, area: int, zone: int) -> bytes:
    return kdf(county_mgmt_key + b"ZONE" + struct.pack(">II", area, zone), 32)


def zone_mgmt_key(county_mgmt_key: bytes, area: int, zone: int) -> bytes:
    """台区管控密钥。从县管控密钥派生，不随网关换槽轮换。"""
    return zone_key(county_mgmt_key, area, zone)


def seed_mgmt(zone_mgmt: bytes, tid: int) -> bytes:
    return kdf(zone_mgmt + b"MGMT" + struct.pack(">Q", tid), 32)


def seed_biz(county_biz_key: bytes, zone: int, tid: int) -> bytes:
    return kdf(county_biz_key + b"BIZ0" + struct.pack(">IQ", zone, tid), 32)


# 流式派生把台区号当作连续槽号。调用方传入 county_zone_count(台区槽数)。
# 台区槽不少于 512 时，这个宽度是 256。
STREAM_COUNTY_WIDTH = 256
CITY_PATH_BITS = 16
CITY_SLOTS = 1 << CITY_PATH_BITS
DELEGATION_GENERATION = 0


def city_slot_path(slot: int) -> tuple[int, ...]:
    """固定 16 位等长路径。任何一个地市都不是另一个地市的祖先。"""
    if not 0 <= slot < CITY_SLOTS:
        raise ValueError("地市槽位越界")
    return tuple((slot >> shift) & 1 for shift in range(CITY_PATH_BITS - 1, -1, -1))


def delegation_body(
    area: int,
    cohort_id: int,
    slot: int,
    n_leaves: int,
    span: int,
    leaf_quota: int | None = None,
) -> bytes:
    quota = n_leaves if leaf_quota is None else leaf_quota
    if quota < 1 or quota > n_leaves:
        raise ValueError("叶子配额越界")
    return b"DELG" + struct.pack(
        ">IIIIIII", area, cohort_id, slot, n_leaves, span, DELEGATION_GENERATION, quota
    )


def provincial_broadcast_root(mk_mgmt: bytes) -> bytes:
    """省级广播树根。只留在密码机里，不交给地市。"""
    return kdf(mk_mgmt + b"PROV", 16)


def descend_key(parent: bytes, bit: int) -> bytes:
    if len(parent) != 16:
        raise ValueError("向下派生的父密钥为 16 字节")
    tag = b"DLFT" if bit == 0 else b"DRGT"
    return kdf(parent + tag, 16)


def city_broadcast_key(mk_mgmt: bytes, path: tuple[int, ...]) -> bytes:
    """从省级广播根单向走到地市节点。路径等长，地市拿不到根，也推不出兄弟地市。"""
    key = provincial_broadcast_root(mk_mgmt)
    for bit in path:
        key = descend_key(key, bit)
    return key


def as_node_key(material: bytes) -> bytes:
    if len(material) == 16:
        return material
    return kdf(material + b"BKEY", 16)


def descend_node(root_key: bytes, node_id: int) -> bytes:
    """节点 1 就是子树根。子节点只能向下派生，推不出父节点和兄弟。"""
    return descend_from(root_key, 1, node_id)


def descend_from(parent_key: bytes, parent_id: int, node_id: int) -> bytes:
    """从已经走到的祖先节点继续向下。父节点密钥推不出更上面的节点。"""
    if parent_id < 1 or node_id < 1:
        raise ValueError("节点号越界")
    key = as_node_key(parent_key)
    if node_id == parent_id:
        return key
    bits: list[int] = []
    node = node_id
    while node > parent_id:
        bits.append(node & 1)
        node //= 2
    if node != parent_id:
        raise ValueError("节点不在这棵子树里")
    for bit in reversed(bits):
        key = descend_key(key, bit)
    return key


def cs_open_key(node_key: bytes) -> bytes:
    """完全子树密文的打开密钥。能解节点 1 的空覆盖，推不出子节点。"""
    return kdf(as_node_key(node_key) + b"CSOP", 16)


def gateway_tree_master(broadcast_key: bytes) -> bytes:
    return kdf(as_node_key(broadcast_key) + b"GWTR", 16)


def node_key_at(master: bytes, node_id: int, generation: int, label: bytes = b"NODE") -> bytes:
    if len(label) != 4:
        raise ValueError("节点标签必须是 4 字节")
    return kdf(master + label + struct.pack(">II", node_id, generation), 16)


def auth_key(auth_leaf: bytes, epoch: int, auth_nonce: bytes) -> bytes:
    """第一参是认证时间树的叶子，不是长期种子。"""
    return kdf(auth_leaf + b"AUTH" + struct.pack(">I", epoch) + auth_nonce, 16)


def ctrl_key(auth_leaf: bytes, epoch: int, auth_nonce: bytes) -> bytes:
    """台区能从认证叶子重算。只保护跳闸、对时，不保护电能量。"""
    return kdf(auth_leaf + b"CTRL" + struct.pack(">I", epoch) + auth_nonce, 16)


def biz_key(leaf: bytes, epoch: int, biz_nonce: bytes) -> bytes:
    return kdf(leaf + b"BIZK" + struct.pack(">I", epoch) + biz_nonce, 16)


def zone_link_key(zone_mgmt: bytes, epoch: int, auth_nonce: bytes) -> bytes:
    return kdf(zone_mgmt + b"ZLNK" + struct.pack(">I", epoch) + auth_nonce, 16)


def ack_key(leaf: bytes, epoch: int, biz_nonce: bytes) -> bytes:
    """业务时间树叶子上的确认密钥。台区没有这片叶子，也没有业务随机数。"""
    return kdf(leaf + b"ACKK" + struct.pack(">I", epoch) + biz_nonce, 16)


def completion_tag(leaf: bytes, zone: int, tid: int, epoch: int, biz_nonce: bytes) -> bytes:
    key = ack_key(leaf, epoch, biz_nonce)
    message = b"ACK1" + struct.pack(">IQI", zone, tid, epoch)
    return hmac_sm3(key, message)[:16]


def make_tid(zone: int, local: int) -> int:
    if not 0 <= local <= 0xFFFF:
        raise ValueError("台区内序号必须落在 16 位")
    return (zone << 16) | local
