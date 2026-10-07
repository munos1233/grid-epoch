"""配电终端与台区网关。网关只有管控域材料，打不开业务域密文。"""

from __future__ import annotations

import hmac
import struct

from .ack import FLAG_MISSING, FLAG_PRESENT, encode_zall, encode_zdet, encode_zexc, xor_tags
from .aead import CryptoError, open_aead, seal
from .crypto import hmac_sm3
from .derive import auth_key, biz_key, completion_tag as tag_bytes, ctrl_key, seed_mgmt, zone_link_key
from .errors import AuthFailed, EpochRejected, ProtocolError, TerminalRevoked
from .merkle import proof_status
from .package import commitment_ok, parse_gateway_package, parse_revocation_package, parse_terminal_package
from .services import GE01, GE03, accept_counter, parse_record, seal_record
from .sdkey import derive_open_key
from .sm9id import enrollment_id, enrollment_message, sign_message, verify_message
from .sm2util import verifier
from .timekey import TimeFrontier, time_leaf


class _EpochAgent:
    def __init__(
        self,
        public_key: str,
        epoch: int,
        nonce: bytes,
        last_timestamp: int,
    ) -> None:
        self.epoch = epoch
        self.nonce = nonce
        self.last_timestamp = last_timestamp
        self.verify_key = public_key
        self._verify = verifier(public_key)

    def _check_signed(self, package, cohort_id: int, area: int) -> None:
        if not self._verify(package.raw_body, package.sm2_signature()):
            raise EpochRejected("SM2 签名无效")
        if package.cohort_id != cohort_id or package.area != area:
            raise EpochRejected("更新簇不匹配")

    def _check_forward(self, package) -> None:
        if package.epoch <= self.epoch:
            raise EpochRejected("拒绝跳回已接受的纪元")
        if package.timestamp <= self.last_timestamp:
            raise EpochRejected("拒绝重放")

    def _open_cover(self, path_order: list[int], path_keys: dict[int, bytes], entries: dict[int, bytes]) -> bytes:
        chosen = next((node for node in path_order if node in entries), None)
        if chosen is None:
            raise TerminalRevoked("逻辑密钥树未覆盖本成员")
        try:
            return open_aead(path_keys[chosen], entries[chosen])
        except CryptoError as exc:
            raise EpochRejected("路径密钥无法解开该报文") from exc

    def _accept_package(self, package) -> bytes:
        if not commitment_ok(package):
            raise EpochRejected("Merkle 证明与纪元头不一致")
        return self._open_epoch(package)

    def _open_epoch(self, package) -> bytes:
        if package.cover == "cs":
            return self._open_cover(self.path_order, self.path_keys, package.entries)
        if package.cover != "sd":
            raise ProtocolError("覆盖种类不合法")
        saw_key = False
        for (root, excluded), blob in package.entries.items():
            key = derive_open_key(self.sd_stubs, self.full_bases, self.sd_secret, root, excluded)
            if key is None:
                continue
            saw_key = True
            try:
                return open_aead(key, blob)
            except CryptoError:
                continue
        if saw_key:
            raise EpochRejected("路径密钥无法解开该报文")
        raise TerminalRevoked("逻辑密钥树未覆盖本成员")


class Terminal(_EpochAgent):
    def __init__(
        self,
        tid: int,
        area: int,
        zone_id: int,
        cohort_id: int,
        leaf: int,
        seed_mgmt: bytes,
        seed_biz: bytes,
        path_order: list[int],
        path_keys: dict[int, bytes],
        epoch: int,
        nonce: bytes,
        last_timestamp: int,
        public_key: str,
        sd_stubs: dict | None = None,
        full_bases: dict | None = None,
        sd_secret: bytes | None = None,
        sm9_user: bytes | None = None,
        sm9_public: bytes | None = None,
        auth_nonce: bytes | None = None,
        tree_n: int = 0,
        device=None,
        provision_blob: bytes | None = None,
    ) -> None:
        super().__init__(public_key, epoch, nonce, last_timestamp)
        self.tid = tid
        self.area = area
        self.zone_id = zone_id
        self.cohort_id = cohort_id
        self.leaf = leaf
        self.seed_mgmt = seed_mgmt
        self.auth_nonce = nonce if auth_nonce is None else auth_nonce
        self.auth_frontier = TimeFrontier(seed_mgmt)
        self.biz_frontier = TimeFrontier(seed_biz)
        if epoch > 0:
            self.auth_frontier.advance_epoch(epoch)
            self.biz_frontier.advance_epoch(epoch)
        self.path_order = path_order
        self.path_keys = dict(path_keys)
        self.sd_stubs = dict(sd_stubs or {})
        self.full_bases = dict(full_bases or {})
        self.sd_secret = b"\x00" * 32 if sd_secret is None else sd_secret
        self.sm9_user = sm9_user
        self.sm9_public = sm9_public
        self.tree_n = tree_n
        self.device = device
        self.provision_blob = provision_blob
        self.uplink = 0

    def discard_signing_key(self) -> None:
        self.sm9_user = None

    def wipe(self, *, release_device: bool = True) -> None:
        """丢掉这台终端还能推出工作密钥的材料。叶子号不在这里处理。"""
        self.discard_signing_key()
        self.seed_mgmt = None
        self.auth_frontier.wipe()
        self.biz_frontier.wipe()
        self.path_keys.clear()
        self.path_order = []
        self.sd_stubs.clear()
        self.full_bases.clear()
        self.sd_secret = None
        self.provision_blob = None
        device = self.device
        self.device = None
        if release_device and device is not None:
            device.discard()

    def sign_enrollment(self, challenge: bytes) -> bytes:
        if self.sm9_user is None or self.sm9_public is None:
            raise ProtocolError("终端没有接入签名密钥")
        identity = enrollment_id(self.area, self.zone_id, self.tid & 0xFFFF)
        return sign_message(self.sm9_user, self.sm9_public, identity, enrollment_message(challenge, self.tid, self.epoch))

    def device_keys(self) -> tuple[bytes, bytes]:
        if self.epoch == 0:
            raise EpochRejected("纪元 0 不能承载业务")
        leaf = self.biz_frontier.current_leaf()
        auth_leaf = self.auth_frontier.current_leaf()
        return (
            auth_key(auth_leaf, self.epoch, self.auth_nonce),
            biz_key(leaf, self.epoch, self.nonce),
        )

    def control_key(self) -> bytes:
        if self.epoch == 0:
            raise EpochRejected("纪元 0 不能承载业务")
        return ctrl_key(self.auth_frontier.current_leaf(), self.epoch, self.auth_nonce)

    def prove(self, challenge: bytes) -> bytes:
        key, _ = self.device_keys()
        return hmac_sm3(key, b"AUTH1" + struct.pack(">Q", self.tid) + challenge)

    def seal_telemetry(self, plaintext: bytes) -> bytes:
        key_auth, key_biz = self.device_keys()
        self.uplink += 1
        return seal_record(GE01, self.tid, self.epoch, self.uplink, key_biz, key_auth, plaintext)

    def seal_control(self, plaintext: bytes) -> bytes:
        key_auth, _key_biz = self.device_keys()
        self.uplink += 1
        return seal_record(GE03, self.tid, self.epoch, self.uplink, self.control_key(), key_auth, plaintext)

    def ack(self) -> bytes:
        key_auth, _ = self.device_keys()
        return hmac_sm3(key_auth, b"ACK0" + struct.pack(">QI", self.tid, self.epoch))

    def completion_tag(self) -> bytes:
        if self.epoch == 0:
            raise EpochRejected("纪元 0 不能承载业务")
        return tag_bytes(self.biz_frontier.current_leaf(), self.zone_id, self.tid, self.epoch, self.nonce)

    def apply(self, blob: bytes) -> None:
        try:
            package = parse_terminal_package(blob)
        except ValueError as exc:
            raise ProtocolError("纪元报文无法解析") from exc
        self._check_signed(package, self.cohort_id, self.area)
        self._check_forward(package)
        plain = self._accept_package(package)
        if len(plain) != 36:
            raise EpochRejected("纪元明文长度错误")
        epoch = struct.unpack(">I", plain[:4])[0]
        if epoch != package.epoch:
            raise EpochRejected("报文体与明文纪元不一致")
        self.auth_frontier.advance_epoch(epoch)
        self.biz_frontier.advance_epoch(epoch)
        self.epoch = epoch
        self.auth_nonce = plain[4:20]
        self.nonce = plain[20:36]
        self.last_timestamp = package.timestamp

    def catch_up(self, packages: list[bytes]) -> None:
        for blob in packages:
            self.apply(blob)


def terminal_from_provision(device, blob: bytes, identity_blob: bytes, record, cohort, verify_key: str) -> Terminal:
    """终端用自己的私钥打开两份封装。地市进程不调用这一步。"""
    from .device import open_identity, open_provision, unpack_material

    if device.public_key != record.device_pub:
        raise ProtocolError("灌装包解不开")
    opened = unpack_material(open_provision(device, blob))
    sm9_user, sm9_public = open_identity(device, identity_blob)
    return Terminal(
        tid=record.tid,
        area=record.area,
        zone_id=record.zone,
        cohort_id=record.cohort_id,
        leaf=record.leaf,
        seed_mgmt=opened["seed_mgmt"],
        seed_biz=opened["seed_biz"],
        path_order=opened["path_order"],
        path_keys=opened["path_keys"],
        sd_stubs=opened["sd_stubs"],
        full_bases=opened["full_bases"],
        sd_secret=opened["sd_secret"],
        sm9_user=sm9_user,
        sm9_public=sm9_public,
        epoch=cohort.epoch,
        nonce=cohort.current_biz(),
        auth_nonce=cohort.current_auth(),
        last_timestamp=cohort.last_timestamp,
        public_key=verify_key,
        tree_n=cohort.terminals.n,
        device=device,
        provision_blob=blob,
    )


class ZoneGateway(_EpochAgent):
    def __init__(
        self,
        area: int,
        zone_id: int,
        cohort_id: int,
        zone_mgmt: bytes,
        leaf: int,
        path_order: list[int],
        path_keys: dict[int, bytes],
        epoch: int,
        nonce: bytes,
        last_timestamp: int,
        public_key: str,
        bitmap_leaves: int,
        sd_stubs: dict | None = None,
        full_bases: dict | None = None,
        sd_secret: bytes | None = None,
        sm9_public: bytes | None = None,
        tree_n: int = 0,
    ) -> None:
        super().__init__(public_key, epoch, nonce, last_timestamp)
        self.area = area
        self.zone_id = zone_id
        self.cohort_id = cohort_id
        self.zone_mgmt = zone_mgmt
        self.leaf = leaf
        self.path_order = path_order
        self.path_keys = dict(path_keys)
        self.sd_stubs = dict(sd_stubs or {})
        self.full_bases = dict(full_bases or {})
        self.sd_secret = b"\x00" * 32 if sd_secret is None else sd_secret
        self.sm9_public = sm9_public
        self.tree_n = tree_n or bitmap_leaves
        self.n_leaves = bitmap_leaves
        self.rev_version = 0
        self.epoch_rev_version = 0
        self.rev_root: bytes | None = None
        self.proofs: dict[int, tuple[bytes, ...]] = {}
        self.leaf_of: dict[int, int] = {}
        self.revoked_tids: set[int] = set()
        self.destroyed_tids: set[int] = set()
        self.uplink_of: dict[int, int] = {}
        self._ack_tags: dict[int, bytes] = {}
        self._ack_conflicts: set[int] = set()
        self._completions: dict[int, tuple[int, bytes, bytes]] = {}
        self.link_key = zone_link_key(zone_mgmt, epoch, nonce)

    def verify_enrollment(self, tid: int, local_index: int, challenge: bytes, signature: bytes, epoch: int) -> bool:
        if self.sm9_public is None or tid in self.revoked_tids or tid in self.destroyed_tids:
            return False
        leaf = self.leaf_of.get(tid)
        if leaf is None or self.leaf_status(leaf) != "live":
            return False
        identity = enrollment_id(self.area, self.zone_id, local_index)
        return verify_message(self.sm9_public, identity, enrollment_message(challenge, tid, epoch), signature)

    def install_zone_mgmt(self, zone_mgmt: bytes) -> None:
        self.zone_mgmt = zone_mgmt
        self.link_key = zone_link_key(zone_mgmt, self.epoch, self.nonce)

    def derive_business_key(self, tid: int) -> bytes:
        raise PermissionError("台区网关不持有业务域主密钥，不能派生业务密钥")

    def bind_terminal(self, tid: int, leaf: int) -> None:
        self.leaf_of[tid] = leaf

    def note_revoked(self, tid: int) -> None:
        self.revoked_tids.add(tid)

    def note_destroyed(self, tid: int) -> None:
        self.destroyed_tids.add(tid)

    def unbind_terminal(self, tid: int) -> None:
        self.leaf_of.pop(tid, None)
        self.revoked_tids.add(tid)

    def sync(self, blob: bytes) -> None:
        try:
            package = parse_gateway_package(blob)
        except ValueError as exc:
            raise ProtocolError("网关报文无法解析") from exc
        self._check_signed(package, self.cohort_id, self.area)
        self._check_forward(package)
        plain = self._accept_package(package)
        if len(plain) != 20:
            raise EpochRejected("纪元明文长度错误")
        epoch = struct.unpack(">I", plain[:4])[0]
        if epoch != package.epoch:
            raise EpochRejected("报文体与明文纪元不一致")
        self.epoch = epoch
        self.nonce = plain[4:]
        self.last_timestamp = package.timestamp
        self.epoch_rev_version = package.rev_version
        self.link_key = zone_link_key(self.zone_mgmt, epoch, self.nonce)
        self.reset_acks()

    def sync_revocation(self, blob: bytes, proofs: dict[int, tuple[bytes, ...]]) -> None:
        try:
            package = parse_revocation_package(blob)
        except ValueError as exc:
            raise ProtocolError("吊销根无法解析") from exc
        if not self._verify(package.raw_body, package.sm2_signature()):
            raise EpochRejected("SM2 签名无效")
        if package.area != self.area or package.cohort_id != self.cohort_id:
            raise EpochRejected("更新簇不匹配")
        if self.epoch_rev_version and package.rev_version != self.epoch_rev_version:
            raise EpochRejected("吊销版本与纪元报文不一致")
        checked: dict[int, tuple[bytes, ...]] = {}
        for leaf, siblings in proofs.items():
            if proof_status(self.n_leaves, package.root, leaf, siblings) is None:
                raise EpochRejected("吊销证明与根不一致")
            checked[leaf] = tuple(siblings)
        self.rev_version = package.rev_version
        self.rev_root = package.root
        self.proofs = checked

    def leaf_status(self, leaf: int) -> str | None:
        if self.rev_root is None:
            return None
        siblings = self.proofs.get(leaf)
        if siblings is None:
            return None
        return proof_status(self.n_leaves, self.rev_root, leaf, siblings)

    def _live(self, tid: int) -> int:
        if tid in self.destroyed_tids:
            raise TerminalRevoked("终端已销毁")
        if tid in self.revoked_tids or (tid >> 16) != self.zone_id:
            raise TerminalRevoked("终端已被吊销或不属于本台区")
        leaf = self.leaf_of.get(tid)
        if leaf is None or self.rev_version != self.epoch_rev_version or self.leaf_status(leaf) != "live":
            raise TerminalRevoked("终端已被吊销或不属于本台区")
        return leaf

    def verify_proof(self, tid: int, challenge: bytes, proof: bytes) -> bool:
        try:
            self._live(tid)
        except TerminalRevoked:
            return False
        if self.epoch == 0:
            return False
        key = auth_key(time_leaf(seed_mgmt(self.zone_mgmt, tid), self.epoch), self.epoch, self.nonce)
        expect = hmac_sm3(key, b"AUTH1" + struct.pack(">Q", tid) + challenge)
        return hmac.compare_digest(expect, proof)

    def accept_and_wrap(self, record: bytes) -> bytes:
        if self.epoch == 0:
            raise EpochRejected("纪元 0 不能承载业务")
        _service, tid, epoch, counter, _sealed, mac, mac_body = parse_record(record)
        self._live(tid)
        if epoch != self.epoch:
            raise EpochRejected("终端尚未跟上当前纪元")
        accept_counter(self.uplink_of.get(tid, 0), counter)
        key = auth_key(time_leaf(seed_mgmt(self.zone_mgmt, tid), epoch), epoch, self.nonce)
        if not hmac.compare_digest(hmac_sm3(key, mac_body), mac):
            raise AuthFailed("终端认证失败")
        self.uplink_of[tid] = counter
        head = b"GE02" + struct.pack(">II", self.zone_id, self.epoch)
        zone_mac = hmac_sm3(self.link_key, head + record)
        return head + record + zone_mac

    def open_control(self, record: bytes) -> bytes:
        service, tid, epoch, counter, sealed, mac, mac_body = parse_record(record)
        if service != GE03:
            raise ProtocolError("不是控制报文")
        self._live(tid)
        if epoch != self.epoch:
            raise EpochRejected("终端尚未跟上当前纪元")
        accept_counter(self.uplink_of.get(tid, 0), counter)
        auth_leaf = time_leaf(seed_mgmt(self.zone_mgmt, tid), epoch)
        key = auth_key(auth_leaf, epoch, self.nonce)
        if not hmac.compare_digest(hmac_sm3(key, mac_body), mac):
            raise AuthFailed("终端认证失败")
        self.uplink_of[tid] = counter
        return open_aead(ctrl_key(auth_leaf, epoch, self.nonce), sealed)

    def open_energy(self, record: bytes) -> bytes:
        raise PermissionError("台区网关打不开电能量")

    def reset_acks(self) -> None:
        self._ack_tags.clear()
        self._ack_conflicts.clear()
        self._completions: dict[int, tuple[int, bytes, bytes]] = {}

    def submit_completion(self, tid: int, local: int, tag: bytes, signature: bytes) -> None:
        """收下终端自己的 SM9 完成签名。网关没有用户私钥，不能代签。"""
        self._live(tid)
        if len(tag) != 16 or not signature or (tid & 0xFFFF) != local:
            raise ProtocolError("完成签名不完整")
        self._completions[tid] = (local, bytes(tag), bytes(signature))

    def completion_audit(self) -> tuple[bytes, bool]:
        from .auditproof import audit_root, verify_completion_audit

        if self.sm9_public is None or not self._completions:
            raise ProtocolError("完成审计为空")
        items = [
            (local, tid, tag, signature)
            for tid, (local, tag, signature) in sorted(self._completions.items())
        ]
        root = audit_root([(tid, tag, signature) for _local, tid, tag, signature in items])
        ok = verify_completion_audit(self.sm9_public, self.area, self.zone_id, self.epoch, items, root)
        return root, ok

    def submit_ack(self, tid: int, ack: bytes, tag: bytes) -> None:
        if self.epoch == 0:
            raise EpochRejected("纪元 0 不能承载业务")
        if len(tag) != 16:
            raise ProtocolError("完成标签长度错误")
        self._live(tid)
        key = auth_key(time_leaf(seed_mgmt(self.zone_mgmt, tid), self.epoch), self.epoch, self.nonce)
        expect = hmac_sm3(key, b"ACK0" + struct.pack(">QI", tid, self.epoch))
        if not hmac.compare_digest(expect, ack):
            raise AuthFailed(f"终端 {tid} 的更新确认无效")
        if tid in self._ack_conflicts:
            return
        previous = self._ack_tags.get(tid)
        if previous is None:
            self._ack_tags[tid] = bytes(tag)
            return
        if previous != tag:
            self._ack_conflicts.add(tid)
            self._ack_tags.pop(tid, None)

    def _collected(self) -> tuple[list[int], dict[int, bytes]]:
        live = []
        for tid in self.leaf_of:
            try:
                self._live(tid)
            except TerminalRevoked:
                continue
            live.append(tid)
        live.sort()
        present = {tid: self._ack_tags[tid] for tid in live if tid in self._ack_tags}
        return live, present

    def completion_report(self) -> bytes:
        if self.epoch == 0:
            raise EpochRejected("纪元 0 不能承载业务")
        live, present = self._collected()
        if not live:
            raise ProtocolError("台区没有在册终端")
        folded = xor_tags([present[tid] for tid in live if tid in present])
        if len(present) == len(live):
            return encode_zall(self.zone_id, self.epoch, len(live), folded, self.link_key)
        missing = [tid & 0xFFFF for tid in live if tid not in present]
        arrived = [tid & 0xFFFF for tid in live if tid in present]
        if len(missing) <= len(arrived):
            return encode_zexc(self.zone_id, self.epoch, FLAG_MISSING, missing, folded, self.link_key)
        return encode_zexc(self.zone_id, self.epoch, FLAG_PRESENT, arrived, folded, self.link_key)

    def detail_report(self) -> bytes:
        if self.epoch == 0:
            raise EpochRejected("纪元 0 不能承载业务")
        _live, present = self._collected()
        items = [(tid & 0xFFFF, present[tid]) for tid in sorted(present)]
        return encode_zdet(self.zone_id, self.epoch, items, self.link_key)
