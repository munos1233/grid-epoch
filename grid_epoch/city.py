"""地市密钥管理。只保存本节点广播密钥、两把委托密钥、委托令牌、本簇注册表和树。"""

from __future__ import annotations

import struct

from .derive import (
    county_biz,
    county_mgmt,
    cs_open_key,
    delegation_body,
    descend_from,
    descend_node,
    make_tid,
    seed_biz,
    seed_mgmt,
    zone_mgmt_key,
)
from .device import pack_material, seal_provision
from .errors import ProtocolError
from .kmc import Cohort, TerminalRecord, member_broadcast_keys
from .sm2util import verifier
from .subtree import county_index, county_node, county_zone_count
from .tree import covers_node, path_nodes


class CountyKMC:
    """只保存本县的两把密钥和本县广播节点。没有地市密钥，也没有省级广播根。"""

    def __init__(self, county_index: int, mgmt: bytes, biz: bytes, broadcast: bytes, node_id: int) -> None:
        self.county_index = county_index
        self.county_mgmt = mgmt
        self.county_biz = biz
        self.broadcast = broadcast
        self.node_id = node_id

    def zone_mgmt(self, area: int, zone_id: int) -> bytes:
        return zone_mgmt_key(self.county_mgmt, area, zone_id)

    def terminal_seed_biz(self, zone_id: int, tid: int) -> bytes:
        return seed_biz(self.county_biz, zone_id, tid)

    def node_key(self, node_id: int) -> bytes:
        """县内节点从本县广播密钥向下走，不从地市树根重算。"""
        return descend_from(self.broadcast, self.node_id, node_id)


class CityKMC:
    def __init__(
        self,
        area: int,
        cohort_id: int,
        slot: int,
        city_mgmt_key: bytes,
        city_biz_key: bytes,
        broadcast_key: bytes,
        token: bytes,
        verify_key: str,
        n_leaves: int,
        registry: dict,
        gateways: dict,
        span: int | None = None,
    ) -> None:
        self.area = area
        self.cohort_id = cohort_id
        self.slot = slot
        self.city_mgmt = city_mgmt_key
        self.city_biz = city_biz_key
        self.broadcast = broadcast_key
        self.token = token
        self.verify_key = verify_key
        self.cohort = Cohort(cohort_id, n_leaves, broadcast_key, span=span)
        self.registry = registry
        self.gateways = gateways
        self.zone_index: dict[int, int] = {}
        self.counties: dict[int, CountyKMC] = {}
        self.firmware: dict[tuple[int, int], int] = {}
        self.leaf_quota = self._quota_from_token()
        self._check_delegation()

    def _quota_from_token(self) -> int:
        prefix = 4 + 24
        if len(self.token) < prefix + 4 + 64:
            raise ProtocolError("委托令牌与范围不符")
        return struct.unpack(">I", self.token[prefix : prefix + 4])[0]

    def _check_delegation(self) -> None:
        body = delegation_body(
            self.area,
            self.cohort_id,
            self.slot,
            self.cohort.terminals.n,
            self.cohort.span,
            self.leaf_quota,
        )
        if len(self.token) != len(body) + 64 or self.token[: len(body)] != body:
            raise ProtocolError("委托令牌与范围不符")
        if not verifier(self.verify_key)(body, self.token[-64:]):
            raise ProtocolError("委托令牌签名无效")

    def county_index_of(self, zone_id: int) -> int:
        zones = self.cohort.terminals.n // self.cohort.span
        return county_index(self.zone_index[zone_id], zones)

    def county_for(self, zone_id: int) -> CountyKMC:
        index = self.county_index_of(zone_id)
        found = self.counties.get(index)
        if found is None:
            node = county_node(self.cohort.terminals.n, self.cohort.span, index)
            found = CountyKMC(
                index,
                county_mgmt(self.city_mgmt, index),
                county_biz(self.city_biz, index),
                descend_node(self.broadcast, node),
                node,
            )
            self.counties[index] = found
        return found

    def zone_mgmt(self, zone_id: int) -> bytes:
        return self.county_for(zone_id).zone_mgmt(self.area, zone_id)

    def zone_leaf_range(self, zone_id: int) -> tuple[int, int]:
        index = self.zone_index[zone_id]
        start = index * self.cohort.span
        return start, start + self.cohort.span

    def register_zone(self, zone_id: int, public_key: str, sm9_public: bytes):
        self._check_delegation()
        if zone_id in self.zone_index:
            raise ProtocolError("台区已经注册")
        index = len(self.zone_index)
        leaf = self.cohort.gateways.allocate(index)
        self.zone_index[zone_id] = index
        self.cohort.zone_leaf[zone_id] = leaf
        self.county_for(zone_id)
        gateway = self._gateway(zone_id, leaf, public_key, sm9_public, self.cohort.epoch, self.cohort.current_auth(), self.cohort.last_timestamp)
        self.gateways[zone_id] = gateway
        return gateway

    def provision(self, zone_id: int, local_index: int, device_public: str):
        """只接收设备公钥，返回种子封装。不打开封装，也不接收 SM9 用户私钥。"""
        self._check_delegation()
        return self._seal(zone_id, local_index, device_public)

    def transfer(self, terminal, new_zone: int, new_local: int, device_public: str):
        self._check_delegation()
        record = self.registry[terminal.tid]
        if record.cohort_id != self.cohort_id:
            raise ProtocolError("终端不属于这个地市")
        if record.destroyed:
            raise ProtocolError("终端已销毁")
        if not record.revoked:
            self.revoke(terminal.tid)
        return self._seal(new_zone, new_local, device_public)

    def mark_destroyed(self, tid: int) -> None:
        record = self.registry[tid]
        if record.cohort_id != self.cohort_id:
            raise ProtocolError("终端不属于这个地市")
        record.destroyed = True

    def revoke(self, tid: int) -> None:
        record = self.registry[tid]
        if record.revoked:
            return
        record.revoked = True
        self.cohort.terminals.revoked.add(record.leaf)
        self.cohort.mark_revocation_dirty()
        gateway = self.gateways.get(record.zone)
        if gateway is not None:
            gateway.note_revoked(tid)

    def revoke_span(self, zone_id: int) -> None:
        self.cohort.terminals.revoke_span(self.zone_index[zone_id])
        self.cohort.mark_revocation_dirty()
        for record in list(self.registry.values()):
            if record.zone == zone_id and record.cohort_id == self.cohort_id:
                self.revoke(record.tid)

    def revoke_batch(self, zone_id: int, batch_index: int) -> None:
        index = self.zone_index[zone_id]
        tree = self.cohort.terminals
        start = index * tree.span + batch_index * tree.batch
        tree.revoke_batch(index, batch_index)
        self.cohort.mark_revocation_dirty()
        self._revoke_leaf_range(start, start + tree.batch)

    def revoke_county(self, county_index: int) -> None:
        tree = self.cohort.terminals
        zones = tree.n // tree.span
        width = county_zone_count(zones)
        start = county_index * width
        tree.revoke_county(county_index)
        self.cohort.mark_revocation_dirty()
        chosen = {zone_id for zone_id, index in self.zone_index.items() if start <= index < start + width}
        for record in list(self.registry.values()):
            if record.cohort_id == self.cohort_id and record.zone in chosen:
                self.revoke(record.tid)

    def revoke_cohort(self) -> None:
        self.cohort.terminals.revoked.update(range(self.cohort.terminals.n))
        self.cohort.gateways.revoked.update(range(self.cohort.gateways.n))
        self.cohort.mark_revocation_dirty()
        for record in list(self.registry.values()):
            if record.cohort_id == self.cohort_id:
                self.revoke(record.tid)

    def replace_gateway(self, zone_id: int):
        old = self.gateways[zone_id]
        index = self.zone_index[zone_id]
        self.cohort.gateways.revoked.add(old.leaf)
        leaf = self.cohort.gateways.allocate(index)
        self.cohort.zone_leaf[zone_id] = leaf
        gateway = self._gateway(
            zone_id,
            leaf,
            old.verify_key,
            old.sm9_public,
            old.epoch,
            old.nonce,
            old.last_timestamp,
        )
        gateway.leaf_of = dict(old.leaf_of)
        gateway.revoked_tids = set(old.revoked_tids)
        gateway.uplink_of = dict(old.uplink_of)
        gateway.destroyed_tids = set(old.destroyed_tids)
        self.gateways[zone_id] = gateway
        return gateway

    def reprovision(self, terminal) -> None:
        record = self.registry[terminal.tid]
        if record.destroyed:
            raise ProtocolError("终端已销毁")
        if record.revoked or record.released:
            raise ProtocolError("已吊销终端不能重新灌装")
        if terminal.zone_id != record.zone or record.cohort_id != self.cohort_id:
            raise ProtocolError("终端与登记不符")
        terminal.seed_mgmt = seed_mgmt(self.zone_mgmt(record.zone), terminal.tid)

    def firmware_version(self, zone_id: int, batch_index: int) -> int:
        return self.firmware.get((zone_id, batch_index), 1)

    def set_firmware(self, zone_id: int, batch_index: int, version: int) -> None:
        count = self.cohort.terminals.span // self.cohort.terminals.batch
        if zone_id not in self.zone_index or not 0 <= batch_index < count or version < 1:
            raise ProtocolError("固件版本无效")
        self.firmware[(zone_id, batch_index)] = version

    def recall_firmware(self, zone_id: int, version: int) -> int:
        """按固件版本摘掉整批。跨台区对齐的两个整批是两条；同一台区里宽度为 2 的不相邻两批是三条。"""
        tree = self.cohort.terminals
        count = tree.span // tree.batch
        recalled = 0
        for batch_index in range(count):
            if self.firmware_version(zone_id, batch_index) == version:
                self.revoke_batch(zone_id, batch_index)
                recalled += 1
        if recalled == 0:
            raise ProtocolError("没有这个固件版本")
        return recalled

    def recall_firmware_batch(self, zone_id: int, batch_index: int) -> None:
        """按供货批次号摘掉整批。版本召回走 recall_firmware。"""
        self.revoke_batch(zone_id, batch_index)

    def adopt_terminal(
        self,
        zone_id: int,
        local_index: int,
        leaf: int,
        device_public: str,
        firmware_batch: int,
        firmware_version: int,
    ) -> TerminalRecord:
        """占用地市进程已经分配的叶子。这里不派生、不保存种子。"""
        self._check_delegation()
        if zone_id not in self.zone_index:
            raise ProtocolError("台区未注册")
        tid = make_tid(zone_id, local_index)
        if tid in self.registry:
            raise ProtocolError("终端序号已经用过")
        if leaf >= self.leaf_quota:
            raise ProtocolError("叶子越界")
        zone_index = self.zone_index[zone_id]
        allocated = self.cohort.terminals.allocate(zone_index)
        if allocated != leaf:
            self.cohort.terminals._cursor[zone_index] = allocated
            raise ProtocolError("叶子号和地市进程不一致")
        record = TerminalRecord(
            tid=tid,
            area=self.area,
            zone=zone_id,
            cohort_id=self.cohort_id,
            leaf=leaf,
            local_index=local_index,
            zone_index=self.zone_index[zone_id],
            device_pub=device_public,
            firmware_batch=firmware_batch,
            firmware_version=firmware_version,
        )
        self.registry[tid] = record
        self.gateways[zone_id].bind_terminal(tid, leaf)
        return record

    def terminal_open_key(self, node_id: int) -> bytes:
        """县内用县广播密钥。县以上只给单向打开密钥，不把地市树根交给终端。"""
        for county in self.counties.values():
            if covers_node(county.node_id, node_id):
                return county.node_key(node_id)
        return cs_open_key(descend_node(self.broadcast, node_id))

    def publish(self, zone_hint: int, sign, escrow_passwords=None, store_offline=None):
        self._check_delegation()
        return self.cohort.publish(
            self.area,
            zone_hint,
            sign,
            escrow_passwords=escrow_passwords,
            cs_key_for=self.terminal_open_key,
            store_offline=store_offline,
        )

    def _revoke_leaf_range(self, start: int, end: int) -> None:
        for record in list(self.registry.values()):
            if record.cohort_id == self.cohort_id and start <= record.leaf < end:
                self.revoke(record.tid)

    def _gateway(self, zone_id: int, leaf: int, public_key: str, sm9_public: bytes, epoch: int, nonce: bytes, last_timestamp: int):
        from .terminal import ZoneGateway

        order, keys = self.cohort.gateways.path_material(leaf)
        stubs, bases, secret = member_broadcast_keys(self.cohort.gateways, leaf)
        return ZoneGateway(
            area=self.area,
            zone_id=zone_id,
            cohort_id=self.cohort_id,
            zone_mgmt=self.zone_mgmt(zone_id),
            leaf=leaf,
            path_order=order,
            path_keys=keys,
            sd_stubs=stubs,
            full_bases=bases,
            sd_secret=secret,
            epoch=epoch,
            nonce=nonce,
            last_timestamp=last_timestamp,
            public_key=public_key,
            bitmap_leaves=self.cohort.terminals.n,
            sm9_public=sm9_public,
            tree_n=self.cohort.gateways.n,
        )

    def _seal(self, zone_id: int, local_index: int, device_public: str):
        if zone_id not in self.zone_index:
            raise ProtocolError("台区未注册")
        tid = make_tid(zone_id, local_index)
        if tid in self.registry and not self.registry[tid].revoked:
            raise ProtocolError("终端已经注册")
        if tid in self.registry:
            raise ProtocolError("终端序号已经用过")
        tree = self.cohort.terminals
        zone_index = self.zone_index[zone_id]
        start, end = tree._span_bounds(zone_index)
        if tree._cursor.get(zone_index, start) >= min(end, self.leaf_quota):
            raise ProtocolError("叶子越界")
        leaf = tree.allocate(zone_index)
        if leaf >= self.leaf_quota:
            raise ProtocolError("叶子越界")
        order = path_nodes(leaf, self.cohort.terminals.n)
        keys = {node_id: self.terminal_open_key(node_id) for node_id in order}
        stubs, bases, secret = member_broadcast_keys(self.cohort.terminals, leaf)
        county = self.county_for(zone_id)
        mgmt = seed_mgmt(county.zone_mgmt(self.area, zone_id), tid)
        biz = county.terminal_seed_biz(zone_id, tid)
        payload = pack_material(mgmt, biz, secret, b"", b"", order, keys, stubs, bases)
        blob = seal_provision(device_public, payload)
        start = self.zone_index[zone_id] * self.cohort.span
        record = TerminalRecord(
            tid=tid,
            area=self.area,
            zone=zone_id,
            cohort_id=self.cohort_id,
            leaf=leaf,
            local_index=local_index,
            zone_index=self.zone_index[zone_id],
            device_pub=device_public,
            firmware_batch=(leaf - start) // self.cohort.terminals.batch,
            firmware_version=self.firmware_version(zone_id, (leaf - start) // self.cohort.terminals.batch),
        )
        self.registry[tid] = record
        self.gateways[zone_id].bind_terminal(tid, leaf)
        return record, blob
