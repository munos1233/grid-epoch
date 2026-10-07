"""省级密钥管理中心。主密钥只留在 HSM 内；终端树和网关树都使用长期子集密钥。"""

from __future__ import annotations

import hmac
import secrets
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

from .ack import FLAG_MISSING, FLAG_PRESENT, parse_detail, parse_report
from .aead import open_aead, seal
from .crypto import hmac_sm3
from .derive import (
    auth_key,
    biz_key,
    city_biz,
    city_broadcast_key,
    city_mgmt,
    city_slot_path,
    completion_tag,
    county_biz,
    ctrl_key,
    delegation_body,
    gateway_tree_master,
    provincial_broadcast_root,
    seed_biz,
    seed_mgmt,
    zone_link_key,
)
from .cosign import CollaborativeSM2
from .custody import open_epoch_nonces, seal_epoch_nonces
from .device import seal_identity
from .errors import AuthFailed, EpochRejected, ProtocolError, TerminalRevoked
from .merkle import RevocationTree, proof_status
from .package import (
    ALG_SM2,
    COVER_CS,
    COVER_SD,
    build_gateway_package,
    build_terminal_package,
    encode_revocation_body,
    seal_signed,
)
from .services import GE01, GE03, accept_counter, parse_record
from .sdkey import cover_subset_key, epoch_secret, full_bases_for_leaf, stubs_for_leaf
from .sm9id import enrollment_id, enrollment_message, new_master, user_sign_key, verify_message
from .subsetdiff import planned_cover
from .timekey import time_leaf
from .subtree import GATEWAY_SLOTS, Subtree, default_span


@dataclass
class TerminalRecord:
    tid: int
    area: int
    zone: int
    cohort_id: int
    leaf: int
    local_index: int
    zone_index: int = 0
    device_pub: str = ""
    firmware_batch: int = 0
    firmware_version: int = 1
    uplink_counter: int = 0
    revoked: bool = False
    released: bool = False
    destroyed: bool = False


@dataclass
class EpochRelease:
    terminal: bytes
    gateway: bytes
    revocation: bytes
    epoch: int
    rev_version: int
    root_key: bytes | None = None
    root_sealed: bytes | None = None


@dataclass
class Cohort:
    """地市更新簇。节点密钥按代数派生，不随纪元滚动。"""

    cohort_id: int
    n_leaves: int
    master: bytes
    epoch: int = 0
    span: int | None = None
    last_timestamp: int = 0
    terminal_packages: list[bytes] = field(default_factory=list)
    zone_leaf: dict[int, int] = field(default_factory=dict)
    rev_version: int = 0
    rev_dirty: bool = True

    def __post_init__(self) -> None:
        span = default_span(self.n_leaves) if self.span is None else self.span
        self.span = span
        self.terminals = Subtree(self.n_leaves, self.master, b"NODE", span)
        self.master = self.terminals.master
        zone_slots = self.n_leaves // span
        self.gateways = Subtree(zone_slots * GATEWAY_SLOTS, gateway_tree_master(self.master), b"GNOD", GATEWAY_SLOTS)
        self.auth_nonces: list[bytes | None] = [b"\x00" * 16]
        self.biz_nonces: list[bytes | None] = [b"\x00" * 16]
        self.nonces = self.biz_nonces
        self.escrow: dict[int, tuple[bytes, bytes]] = {}
        self.rev_package: bytes | None = None
        self.rev_tree: RevocationTree | None = None

    def mark_revocation_dirty(self) -> None:
        self.rev_dirty = True

    def _ensure_revocation(self, area: int, sign) -> None:
        if not self.rev_dirty and self.rev_package is not None and self.rev_tree is not None:
            return
        self.rev_version += 1
        self.rev_tree = RevocationTree(self.terminals.n, self.terminals.revoked)
        body = encode_revocation_body(area, self.cohort_id, self.rev_version, self.rev_tree.root())
        self.rev_package = seal_signed(body, sign)
        self.rev_dirty = False

    def revocation_proof(self, leaf: int) -> tuple[bytes, ...]:
        if self.rev_tree is None:
            raise ProtocolError("吊销根尚未签发")
        return self.rev_tree.proof(leaf)

    def current_auth(self) -> bytes:
        return self._nonce_at(self.auth_nonces, self.epoch)

    def current_biz(self) -> bytes:
        return self._nonce_at(self.biz_nonces, self.epoch)

    def current_nonce(self) -> bytes:
        return self.current_biz()

    def _nonce_at(self, series: list[bytes | None], epoch: int) -> bytes:
        if not 0 <= epoch < len(series) or series[epoch] is None:
            raise EpochRejected("该纪元的随机数已销毁")
        return series[epoch]

    def drop_expired(self, before_epoch: int) -> None:
        if before_epoch > self.epoch:
            raise ProtocolError("不能销毁当前纪元的随机数")
        if before_epoch < 0:
            raise ProtocolError("销毁窗口无效")
        for epoch in range(1, before_epoch):
            self.auth_nonces[epoch] = None
            self.biz_nonces[epoch] = None

    def _next_timestamp(self, timestamp: int | None) -> int:
        if timestamp is None:
            timestamp = time.time_ns() // 1_000_000
        if timestamp <= self.last_timestamp:
            timestamp = self.last_timestamp + 1
        return timestamp

    def publish(
        self,
        area: int,
        zone_hint: int,
        sign,
        timestamp: int | None = None,
        escrow_passwords: tuple[str, str] | None = None,
        cs_key_for=None,
        store_offline=None,
    ) -> EpochRelease:
        if escrow_passwords is None:
            raise ProtocolError("发布前要先封装两份口令")
        auth_nonce = secrets.token_bytes(16)
        biz_nonce = secrets.token_bytes(16)
        target = self.epoch + 1
        gateway_plain = struct.pack(">I", target) + auth_nonce
        terminal_plain = gateway_plain + biz_nonce
        stamp = self._next_timestamp(timestamp)
        self._ensure_revocation(area, sign)
        terminal_cover, terminal_entries, root_key, root_sealed = _seal_epoch(
            self.terminals, terminal_plain, cs_key_for
        )
        gateway_cover, gateway_entries, _, _ = _seal_epoch(self.gateways, gateway_plain)
        release = EpochRelease(
            terminal=build_terminal_package(
                area, zone_hint, self.cohort_id, target, stamp, self.rev_version, terminal_cover, terminal_entries, sign
            ),
            gateway=build_gateway_package(
                area, self.cohort_id, target, stamp, self.rev_version, gateway_cover, gateway_entries, sign
            ),
            revocation=self.rev_package,
            epoch=target,
            rev_version=self.rev_version,
            root_key=root_key,
            root_sealed=root_sealed,
        )
        self.auth_nonces.append(auth_nonce)
        self.biz_nonces.append(biz_nonce)
        sealed_a, sealed_b, offline = seal_epoch_nonces(auth_nonce, biz_nonce, escrow_passwords[0], escrow_passwords[1])
        self.escrow[target] = (sealed_a, sealed_b)
        if store_offline is not None:
            store_offline(target, offline)
        del offline
        self.epoch = target
        self.last_timestamp = stamp
        self.terminal_packages.append(release.terminal)
        return release

    def packages_since(self, epoch: int) -> list[bytes]:
        if not 0 <= epoch <= self.epoch:
            raise ProtocolError("追赶起点无效")
        return self.terminal_packages[epoch:]


def _seal_epoch(tree: Subtree, plaintext: bytes, cs_key_for=None) -> tuple[int, list, bytes | None, bytes | None]:
    kind, subsets = planned_cover(tree.n, set(tree.revoked), tree.batch)
    if not subsets:
        raise ProtocolError("覆盖集为空，没有仍在册的成员")
    if kind == "cs":
        entries = []
        root_key = None
        root_sealed = None
        for node_id in subsets:
            key = tree.node_key(node_id) if cs_key_for is None else cs_key_for(node_id)
            blob = seal(key, plaintext)
            entries.append((node_id, blob))
            if node_id == 1:
                root_key = key
                root_sealed = blob
        return COVER_CS, entries, root_key, root_sealed
    secret = epoch_secret(tree.master, 0)
    entries = [
        (root, excluded, seal(cover_subset_key(tree.master, secret, root, excluded), plaintext))
        for root, excluded in subsets
    ]
    return COVER_SD, entries, None, None


def member_broadcast_keys(tree: Subtree, leaf: int):
    return (
        stubs_for_leaf(tree.n, leaf, tree.master),
        full_bases_for_leaf(tree.n, leaf, tree.master),
        epoch_secret(tree.master, 0),
    )


class HSM:
    """省级密码机边界：管控域与业务域主密钥不可交叉导出。"""

    def __init__(
        self,
        mk_mgmt: bytes | None = None,
        mk_biz: bytes | None = None,
        sm9_master: bytes | None = None,
    ) -> None:
        self._mk_mgmt = secrets.token_bytes(32) if mk_mgmt is None else mk_mgmt
        self._mk_biz = secrets.token_bytes(32) if mk_biz is None else mk_biz
        if sm9_master is None:
            self._sm9_master, self._sm9_public = new_master()
        else:
            from .sm9id import master_public

            self._sm9_master = sm9_master
            self._sm9_public = master_public(sm9_master)
        self.cosign = CollaborativeSM2()

    @property
    def public_key(self) -> str:
        return self.cosign.public_key

    def city_mgmt_key(self, cohort_id: int) -> bytes:
        return city_mgmt(self._mk_mgmt, cohort_id)

    def city_biz_key(self, area: int, cohort_id: int) -> bytes:
        return city_biz(self._mk_biz, area, cohort_id)

    def broadcast_root(self) -> bytes:
        return provincial_broadcast_root(self._mk_mgmt)

    def city_node_key(self, slot: int) -> bytes:
        try:
            path = city_slot_path(slot)
        except ValueError as exc:
            raise ProtocolError("地市槽位越界") from exc
        return city_broadcast_key(self._mk_mgmt, path)

    def city_master(self, cohort_id: int) -> bytes:
        return self.city_mgmt_key(cohort_id)

    def terminal_seed_biz(self, area: int, cohort_id: int, county_index: int, zone: int, tid: int) -> bytes:
        return seed_biz(county_biz(self.city_biz_key(area, cohort_id), county_index), zone, tid)

    def issue_delegation(
        self,
        area: int,
        cohort_id: int,
        slot: int,
        n_leaves: int,
        span: int,
        leaf_quota: int | None = None,
    ) -> bytes:
        body = delegation_body(area, cohort_id, slot, n_leaves, span, leaf_quota)
        return body + self.cosign.sign(body)

    def seal_user_key(self, device_public: str, area: int, zone: int, local: int) -> bytes:
        identity = enrollment_id(area, zone, local)
        user_key = user_sign_key(self._sm9_master, identity)
        return seal_identity(device_public, user_key, self._sm9_public)

    @property
    def sm9_public(self) -> bytes:
        return self._sm9_public

    def sign(self, data: bytes) -> list[tuple[int, bytes]]:
        return [(ALG_SM2, self.cosign.sign(data))]


class ProvincialKMC:
    def __init__(self, area: int = 330100) -> None:
        self.area = area
        self.hsm = HSM()
        self.cohorts: dict[int, Cohort] = {}
        self.cities: dict[int, object] = {}
        self.zone_cohort: dict[int, int] = {}
        self.gateways: dict[int, object] = {}
        self.registry: dict[int, TerminalRecord] = {}
        self.confirmed: dict[int, set[int]] = {}
        self._escrow_passwords: tuple[str, str] | None = None
        self._offline_dir: Path | None = None

    def arm_escrow(self, password_a: str, password_b: str, offline_dir: str | Path | None = None) -> None:
        if not password_a or not password_b or password_a == password_b:
            raise ProtocolError("两份口令必须不同且非空")
        self._escrow_passwords = (password_a, password_b)
        if offline_dir is not None:
            self._offline_dir = Path(offline_dir)

    def create_cohort(
        self, cohort_id: int, n_leaves: int, span: int | None = None, leaf_quota: int | None = None
    ) -> Cohort:
        from .city import CityKMC
        from .subtree import default_span

        if len(self.cities) >= (1 << 16):
            raise ProtocolError("地市槽位已用尽")
        slot = len(self.cities)
        chosen = default_span(n_leaves) if span is None else span
        token = self.hsm.issue_delegation(self.area, cohort_id, slot, n_leaves, chosen, leaf_quota)
        city = CityKMC(
            self.area,
            cohort_id,
            slot,
            self.hsm.city_mgmt_key(cohort_id),
            self.hsm.city_biz_key(self.area, cohort_id),
            self.hsm.city_node_key(slot),
            token,
            self.hsm.public_key,
            n_leaves,
            self.registry,
            self.gateways,
            chosen,
        )
        self.cities[cohort_id] = city
        self.cohorts[cohort_id] = city.cohort
        return city.cohort

    def register_zone(self, zone_id: int, cohort_id: int):
        gateway = self.cities[cohort_id].register_zone(zone_id, self.hsm.public_key, self.hsm.sm9_public)
        self.zone_cohort[zone_id] = cohort_id
        return gateway

    def enroll(self, zone_id: int, local_index: int):
        from .device import DeviceKey
        from .terminal import terminal_from_provision

        cohort_id = self.zone_cohort[zone_id]
        device = DeviceKey()
        identity_blob = self.hsm.seal_user_key(device.public_key, self.area, zone_id, local_index)
        record, blob = self.cities[cohort_id].provision(zone_id, local_index, device.public_key)
        return terminal_from_provision(
            device, blob, identity_blob, record, self.cohorts[cohort_id], self.hsm.public_key
        )

    def revoke(self, tid: int) -> None:
        record = self.registry[tid]
        if record.released:
            raise ProtocolError("终端叶子已经回收")
        self.cities[record.cohort_id].revoke(tid)

    def revoke_span(self, zone_id: int) -> None:
        self.cities[self.zone_cohort[zone_id]].revoke_span(zone_id)

    def revoke_gateway(self, zone_id: int):
        """作废当前网关槽，把下一槽交给新网关。台区管控密钥和终端路径密钥不动。"""
        return self.cities[self.zone_cohort[zone_id]].replace_gateway(zone_id)

    def revoke_cohort(self, cohort_id: int) -> None:
        self.cities[cohort_id].revoke_cohort()

    def revoke_county(self, cohort_id: int, county_index: int) -> None:
        self.cities[cohort_id].revoke_county(county_index)

    def revoke_batch(self, zone_id: int, batch_index: int) -> None:
        self.cities[self.zone_cohort[zone_id]].revoke_batch(zone_id, batch_index)

    def recall_firmware_batch(self, zone_id: int, batch_index: int) -> None:
        self.cities[self.zone_cohort[zone_id]].recall_firmware_batch(zone_id, batch_index)

    def set_firmware(self, zone_id: int, batch_index: int, version: int) -> None:
        self.cities[self.zone_cohort[zone_id]].set_firmware(zone_id, batch_index, version)

    def recall_firmware(self, zone_id: int, version: int) -> int:
        return self.cities[self.zone_cohort[zone_id]].recall_firmware(zone_id, version)

    def destroy_record(self, tid: int) -> None:
        record = self.registry[tid]
        record.destroyed = True

    def reprovision(self, terminal) -> None:
        self.cities[self.zone_cohort[terminal.zone_id]].reprovision(terminal)

    def transfer(self, terminal, new_zone: int, new_local: int):
        from .terminal import terminal_from_provision

        record = self.registry[terminal.tid]
        if record.destroyed:
            raise ProtocolError("终端已销毁")
        if terminal.device is None:
            raise ProtocolError("终端没有设备密钥，不能割接")
        city = self.cities[record.cohort_id]
        identity_blob = self.hsm.seal_user_key(terminal.device.public_key, self.area, new_zone, new_local)
        moved, blob = city.transfer(terminal, new_zone, new_local, terminal.device.public_key)
        return terminal_from_provision(
            terminal.device, blob, identity_blob, moved, city.cohort, self.hsm.public_key
        )

    def publish(self, cohort_id: int, zone_hint: int = 0) -> EpochRelease:
        if self._escrow_passwords is None:
            raise ProtocolError("发布前要先封装两份口令")
        release = self.cities[cohort_id].publish(
            zone_hint,
            self.hsm.sign,
            self._escrow_passwords,
            store_offline=self._store_nonce_share,
        )
        self.confirmed[cohort_id] = set()
        return release

    def _store_nonce_share(self, epoch: int, share: bytes) -> None:
        if self._offline_dir is None:
            return
        self._offline_dir.mkdir(parents=True, exist_ok=True)
        (self._offline_dir / f"nonce_{epoch}.bin").write_bytes(share)

    def recall_plan(self, cohort_id: int) -> tuple[str, int]:
        tree = self.cohorts[cohort_id].terminals
        kind, subsets = planned_cover(tree.n, set(tree.revoked), tree.batch)
        return kind, len(subsets)

    def drop_expired(self, cohort_id: int, before_epoch: int) -> None:
        self.cohorts[cohort_id].drop_expired(before_epoch)

    def recover_nonces(self, cohort_id: int, epoch: int, password_a: str, password_b: str) -> tuple[bytes, bytes]:
        pair = self.cohorts[cohort_id].escrow.get(epoch)
        if pair is None:
            raise ProtocolError("该纪元没有托管包")
        return open_epoch_nonces(pair[0], pair[1], password_a, password_b)

    def forward_zone(self, zone_id: int, terminal_blob: bytes) -> list[bytes]:
        from .package import forward_zone

        city = self.cities[self.zone_cohort[zone_id]]
        start, end = city.zone_leaf_range(zone_id)
        return forward_zone(terminal_blob, city.cohort.terminals.n, start, end)

    def device_keys(self, tid: int) -> tuple[bytes, bytes]:
        record = self.registry[tid]
        cohort = self.cohorts[record.cohort_id]
        if cohort.epoch == 0:
            raise EpochRejected("纪元 0 不能承载业务")
        seed_m, seed_b = self._seeds(record)
        auth_leaf = time_leaf(seed_m, cohort.epoch)
        leaf = time_leaf(seed_b, cohort.epoch)
        return auth_key(auth_leaf, cohort.epoch, cohort.current_auth()), biz_key(leaf, cohort.epoch, cohort.current_biz())

    def control_key(self, tid: int) -> bytes:
        record = self.registry[tid]
        cohort = self.cohorts[record.cohort_id]
        if cohort.epoch == 0:
            raise EpochRejected("纪元 0 不能承载业务")
        seed_m, _seed_b = self._seeds(record)
        return ctrl_key(time_leaf(seed_m, cohort.epoch), cohort.epoch, cohort.current_auth())

    def business_key_at(self, tid: int, epoch: int) -> bytes:
        record = self.registry[tid]
        cohort = self.cohorts[record.cohort_id]
        if not 0 < epoch <= cohort.epoch:
            raise EpochRejected("纪元超出已发布范围")
        _seed_m, seed_b = self._seeds(record)
        return biz_key(time_leaf(seed_b, epoch), epoch, cohort._nonce_at(cohort.biz_nonces, epoch))

    def _seeds(self, record: TerminalRecord) -> tuple[bytes, bytes]:
        city = self.cities[record.cohort_id]
        county_index = city.county_index_of(record.zone)
        return seed_mgmt(city.zone_mgmt(record.zone), record.tid), self.hsm.terminal_seed_biz(
            record.area, record.cohort_id, county_index, record.zone, record.tid
        )

    def _zone_mgmt(self, zone_id: int) -> bytes:
        return self.cities[self.zone_cohort[zone_id]].zone_mgmt(zone_id)

    def open_uplink(self, blob: bytes) -> bytes:
        if len(blob) < 12 + 32 or blob[:4] != b"GE02":
            raise ProtocolError("上行报文格式错误")
        zone_id, epoch = struct.unpack_from(">II", blob, 4)
        if epoch == 0:
            raise EpochRejected("纪元 0 不能承载业务")
        if zone_id not in self.zone_cohort:
            raise ProtocolError("台区未注册")
        record_bytes = blob[12:-32]
        zone_mac = blob[-32:]
        cohort = self.cohorts[self.zone_cohort[zone_id]]
        if epoch != cohort.epoch:
            raise EpochRejected("台区链路纪元与主站不一致")
        link = zone_link_key(self._zone_mgmt(zone_id), epoch, cohort.current_auth())
        if not hmac.compare_digest(hmac_sm3(link, blob[:-32]), zone_mac):
            raise AuthFailed("台区链路认证失败")
        service, tid, rec_epoch, counter, sealed, mac, mac_body = parse_record(record_bytes)
        if rec_epoch != epoch:
            raise EpochRejected("终端业务纪元与链路不一致")
        record = self.registry.get(tid)
        if record is not None and record.destroyed:
            raise TerminalRevoked("终端已销毁")
        if (
            record is None
            or record.revoked
            or record.released
            or record.zone != zone_id
            or record.leaf in cohort.terminals.revoked
        ):
            raise TerminalRevoked("终端不在该台区的在册集合内")
        accept_counter(record.uplink_counter, counter)
        auth, business = self.device_keys(tid)
        if not hmac.compare_digest(hmac_sm3(auth, mac_body), mac):
            raise AuthFailed("终端认证失败")
        if service == GE01:
            plain = open_aead(business, sealed)
        elif service == GE03:
            plain = open_aead(self.control_key(tid), sealed)
        else:
            raise ProtocolError("服务号不合法")
        record.uplink_counter = counter
        return plain

    def accept_report(self, zone_id: int, token: bytes) -> set[int]:
        report = parse_report(token)
        if report.zone_id != zone_id:
            raise AuthFailed("确认里的台区号不一致")
        cohort = self._check_zone_mac(zone_id, report.epoch, report.body, report.mac)
        live = self._live_records(zone_id)
        if report.kind == "full":
            if report.count != len(live):
                raise ProtocolError("完成帧台数与在册集合不一致")
            expected = live
        else:
            expected = self._partial_records(report.flag, report.locals_, live)
        folded = self._fold_tags(expected, cohort.epoch, cohort.current_biz())
        if not hmac.compare_digest(folded, report.tag_xor):
            raise AuthFailed("完成标签与在册集合不一致")
        tids = {record.tid for record in expected}
        self.confirmed.setdefault(cohort.cohort_id, set()).update(tids)
        return tids

    def localize_report(self, zone_id: int, token: bytes) -> set[int]:
        detail = parse_detail(token)
        if detail.zone_id != zone_id:
            raise AuthFailed("确认里的台区号不一致")
        cohort = self._check_zone_mac(zone_id, detail.epoch, detail.body, detail.mac)
        live = {record.local_index: record for record in self._live_records(zone_id)}
        nonce = cohort.current_biz()
        matched: list[TerminalRecord] = []
        seen: set[int] = set()
        for local, tag in detail.items:
            if local in seen:
                raise ProtocolError("确认里的终端重复")
            seen.add(local)
            record = live.get(local)
            if record is None:
                continue
            expect = self._one_tag(record, cohort.epoch, nonce)
            if hmac.compare_digest(expect, tag):
                matched.append(record)
        tids = {record.tid for record in matched}
        self.confirmed.setdefault(cohort.cohort_id, set()).update(tids)
        return tids

    def _check_zone_mac(self, zone_id: int, epoch: int, body: bytes, mac: bytes) -> Cohort:
        if zone_id not in self.zone_cohort:
            raise ProtocolError("台区未注册")
        if epoch == 0:
            raise EpochRejected("纪元 0 不能承载业务")
        cohort = self.cohorts[self.zone_cohort[zone_id]]
        if epoch != cohort.epoch:
            raise EpochRejected("确认纪元与主站不一致")
        link = zone_link_key(self._zone_mgmt(zone_id), epoch, cohort.current_auth())
        if not hmac.compare_digest(hmac_sm3(link, body), mac):
            raise AuthFailed("台区更新确认无效")
        return cohort

    def _live_records(self, zone_id: int) -> list[TerminalRecord]:
        cohort = self.cohorts[self.zone_cohort[zone_id]]
        revoked_leaves = cohort.terminals.revoked
        return [
            record
            for record in self.registry.values()
            if record.zone == zone_id
            and not record.revoked
            and not record.released
            and not record.destroyed
            and record.leaf not in revoked_leaves
        ]

    def _partial_records(self, flag: int, locals_: tuple[int, ...], live: list[TerminalRecord]) -> list[TerminalRecord]:
        if len(set(locals_)) != len(locals_):
            raise ProtocolError("确认里的终端重复")
        by_local = {record.local_index: record for record in live}
        if flag == FLAG_MISSING:
            missing = set(locals_)
            return [record for record in live if record.local_index not in missing]
        if flag != FLAG_PRESENT:
            raise ProtocolError("差额帧种类不合法")
        chosen = []
        for local in locals_:
            record = by_local.get(local)
            if record is None:
                raise TerminalRevoked("确认包含已吊销或不属于该台区的终端")
            chosen.append(record)
        return chosen

    def _one_tag(self, record: TerminalRecord, epoch: int, nonce: bytes) -> bytes:
        _seed_m, seed = self._seeds(record)
        return completion_tag(time_leaf(seed, epoch), record.zone, record.tid, epoch, nonce)

    def _fold_tags(self, records: list[TerminalRecord], epoch: int, nonce: bytes) -> bytes:
        folded = bytearray(16)
        for record in records:
            for index, value in enumerate(self._one_tag(record, epoch, nonce)):
                folded[index] ^= value
        return bytes(folded)

    def verify_enrollment(self, tid: int, challenge: bytes, signature: bytes, epoch: int) -> bool:
        record = self.registry.get(tid)
        if record is None or record.revoked or record.released or record.destroyed:
            return False
        cohort = self.cohorts[record.cohort_id]
        if cohort.rev_tree is None:
            return False
        proof = cohort.rev_tree.proof(record.leaf)
        if proof_status(cohort.terminals.n, cohort.rev_tree.root(), record.leaf, proof) != "live":
            return False
        message = enrollment_message(challenge, tid, epoch)
        identity = enrollment_id(record.area, record.zone, record.local_index)
        return verify_message(self.hsm.sm9_public, identity, message, signature)

    def proofs_for_zone(self, zone_id: int) -> dict[int, tuple[bytes, ...]]:
        cohort = self.cohorts[self.zone_cohort[zone_id]]
        gateway = self.gateways[zone_id]
        return {leaf: cohort.revocation_proof(leaf) for leaf in gateway.leaf_of.values()}


def _split_terminal_record(record: bytes):
    """兼容旧调用：返回 tid、纪元、密文、MAC、被 MAC 覆盖的前缀。"""
    _service, tid, epoch, _counter, sealed, mac, mac_body = parse_record(record)
    return tid, epoch, sealed, mac, mac_body
