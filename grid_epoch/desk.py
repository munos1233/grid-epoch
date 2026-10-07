"""操作台背后的同一套省级主站。档案进库，种子不进库。"""

from __future__ import annotations

import secrets
from pathlib import Path

from .ack import encode_zall, xor_tags
from .auditproof import sign_completion
from .custody import restore_masters, seal_masters
from .custodian import ShareSink, open_share_sink
from .errors import AuthFailed, ProtocolError
from .kmc import ProvincialKMC
from .package import parse_gateway_package, parse_revocation_package, parse_terminal_package
from .session import ProvisionSession
from .store import RegistryStore


_COVER_NAME = {"cs": "完全子树", "sd": "子集差"}


class OperatorDesk:
    def __init__(self, directory: str | Path, area: int = 330100, sink: ShareSink | None = None) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.kmc = ProvincialKMC(area=area)
        self.store = RegistryStore(self.directory / "registry.sqlite")
        self.store.clear_audit()
        self.terminals: dict[tuple[int, int], object] = {}
        self.release = None
        self.withheld: dict[int, int] = {}
        self.kmc.create_cohort(1, 32)
        self._sink = sink
        if self._sink is None:
            self._sink, _offline = open_share_sink()
            del _offline
        try:
            self.kmc._store_nonce_share = self._hand_nonce
            self.session = ProvisionSession(self.kmc, 1)
            for zone in (42, 43, 44):
                self.kmc.register_zone(zone, 1)
                self.session.register(zone)
                for local in range(4):
                    terminal = self.session.enroll(zone, local)
                    self.terminals[(zone, local)] = terminal
                    self._mirror(terminal.tid)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        session = getattr(self, "session", None)
        if session is not None:
            session.close()
            self.session = None
        sink = getattr(self, "_sink", None)
        if sink is not None:
            sink.close()
            self._sink = None
        store = getattr(self, "store", None)
        if store is not None:
            store.close()

    def _hand_nonce(self, epoch: int, share: bytes) -> None:
        self._sink.put_nonce(epoch, share)

    def seal(self, password_a: str, password_b: str) -> None:
        blob_a, blob_b, offline = seal_masters(
            self.kmc.hsm._mk_mgmt,
            self.kmc.hsm._mk_biz,
            self.kmc.hsm._sm9_master,
            password_a,
            password_b,
        )
        (self.directory / "share_a.bin").write_bytes(blob_a)
        (self.directory / "share_b.bin").write_bytes(blob_b)
        self._sink.put_masters(offline)
        del offline
        self.kmc.arm_escrow(password_a, password_b)
        self.kmc._escrow_passwords = None
        self.store.audit("封装主密钥", "两份口令分片已写入本机，第三份交给保管进程，未进入值班台目录")

    def restore(self, password_a: str, password_b: str) -> None:
        blob_a = (self.directory / "share_a.bin").read_bytes()
        blob_b = (self.directory / "share_b.bin").read_bytes()
        mk_mgmt, mk_biz, sm9_master = restore_masters(blob_a, blob_b, password_a, password_b)
        if (
            mk_mgmt != self.kmc.hsm._mk_mgmt
            or mk_biz != self.kmc.hsm._mk_biz
            or sm9_master != self.kmc.hsm._sm9_master
        ):
            raise AuthFailed("恢复出的主密钥与在运主站不一致")
        self.store.audit("恢复主密钥", "两份口令核对通过")

    def status(self) -> dict:
        cohort = self.kmc.cohorts[1]
        behind = 0
        for zone_id, gateway in self.kmc.gateways.items():
            if gateway.epoch < cohort.epoch:
                behind += 1
        packages = None
        if self.release is not None:
            packages = {
                "terminal": self._checked(self.release.terminal, parse_terminal_package),
                "gateway": self._checked(self.release.gateway, parse_gateway_package),
                "revocation": self._checked(self.release.revocation, parse_revocation_package),
            }
        kind, subsets = self.kmc.recall_plan(1)
        watch = [zone_id for zone_id, gateway in self.kmc.gateways.items() if gateway.epoch < cohort.epoch]
        return {
            "epoch": cohort.epoch,
            "rev_version": cohort.rev_version,
            "behind_zones": behind,
            "watch": watch,
            "cover": _COVER_NAME[kind],
            "recall": {"kind": kind, "subsets": subsets},
            "packages": packages,
        }

    def members(self, zone: int) -> list[dict]:
        confirmed = self.kmc.confirmed.get(1, set())
        held = self.withheld.get(zone)
        rows = []
        pairs = sorted(
            (local, terminal) for (zone_id, local), terminal in self.terminals.items() if zone_id == zone
        )
        for local, terminal in pairs:
            record = self.kmc.registry[terminal.tid]
            if record.released:
                state = "已回收"
            elif record.destroyed:
                state = "已销毁"
            elif record.revoked:
                state = "已吊销"
            elif record.tid in confirmed:
                state = "已确认"
            elif held == local:
                state = "被扣下"
            else:
                state = "在册"
            rows.append({"local": local, "leaf": record.leaf, "state": state})
        return rows

    def zones(self, page: int, size: int = 2) -> dict:
        rows, total = self.store.zone_page(page, size)
        cohort_epoch = self.kmc.cohorts[1].epoch
        confirmed = self.kmc.confirmed.get(1, set())
        for row in rows:
            gateway = self.kmc.gateways[row["zone"]]
            row["acked"] = sum(1 for tid in confirmed if (tid >> 16) == row["zone"])
            row["behind"] = gateway.epoch < cohort_epoch
        return {"page": page, "size": size, "total": total, "zones": rows}

    def lookup(self, zone: int, local_index: int) -> dict | None:
        row = self.store.find_terminal(zone, local_index)
        if row is None:
            return None
        record = self.kmc.registry[row["tid"]]
        return {
            "zone": record.zone,
            "local_index": record.local_index,
            "tid": record.tid,
            "leaf": record.leaf,
            "cohort": record.cohort_id,
            "revoked": record.revoked,
            "released": record.released,
            "destroyed": record.destroyed,
        }

    def publish(self, password_a: str, password_b: str) -> dict:
        self.kmc.arm_escrow(password_a, password_b)
        try:
            self.release = self.kmc.publish(1)
        finally:
            self.kmc._escrow_passwords = None
        self.withheld.clear()
        self.store.audit("发布", f"纪元 {self.release.epoch}，吊销版本 {self.release.rev_version}")
        return self.status()

    def revoke(self, zone: int, local_index: int) -> dict:
        terminal = self._live(zone, local_index)
        self.session.revoke(terminal.tid)
        self._mirror(terminal.tid)
        self.store.audit("吊销", f"台区 {zone} 序号 {local_index}")
        return self.lookup(zone, local_index)

    def replace_meter(self, zone: int, local_index: int, new_local: int) -> dict:
        old = self._live(zone, local_index)
        self.session.revoke(old.tid)
        terminal = self.session.enroll(zone, new_local)
        self.terminals[(zone, new_local)] = terminal
        self._mirror(old.tid)
        self._mirror(terminal.tid)
        self.store.audit("换表", f"台区 {zone} 序号 {local_index} 换成 {new_local}，新叶子 {terminal.leaf}")
        return self.lookup(zone, new_local)

    def transfer_meter(self, zone: int, local_index: int, new_zone: int, new_local: int) -> dict:
        old = self._live(zone, local_index)
        terminal = self.session.transfer(old, new_zone, new_local)
        self.terminals[(new_zone, new_local)] = terminal
        self._mirror(old.tid)
        self._mirror(terminal.tid)
        self.store.audit("割接", f"台区 {zone} 序号 {local_index} 迁到台区 {new_zone} 序号 {new_local}")
        return self.lookup(new_zone, new_local)

    def destroy_meter(self, zone: int, local_index: int) -> dict:
        terminal = self._live(zone, local_index)
        leaf = terminal.leaf
        self.session.mark_destroyed(terminal.tid)
        self.session.drop(terminal.tid)
        self.kmc.gateways[zone].note_destroyed(terminal.tid)
        self.kmc.destroy_record(terminal.tid)
        self._mirror(terminal.tid)
        self.store.audit("销毁档案", f"台区 {zone} 序号 {local_index} 已销毁，叶子 {leaf} 保留")
        return self.lookup(zone, local_index)

    def archive_audit(self, before_id: int) -> dict:
        moved = self.store.archive_before(before_id)
        return {"moved": moved}

    def set_firmware(self, zone: int, batch_index: int, version: int) -> dict:
        self.kmc.set_firmware(zone, batch_index, version)
        return {"zone": zone, "batch": batch_index, "version": version}

    def recall_firmware(self, zone: int, version: int) -> dict:
        city = self.kmc.cities[1]
        width = city.cohort.terminals.span // city.cohort.terminals.batch
        chosen = [index for index in range(width) if city.firmware_version(zone, index) == version]
        if not chosen:
            raise ProtocolError("没有这个固件版本")
        for batch_index in chosen:
            self.session.revoke_batch(zone, batch_index)
        batches = len(chosen)
        for (zone_id, _local), terminal in self.terminals.items():
            if zone_id == zone:
                self._mirror(terminal.tid)
        kind, subsets = self.kmc.recall_plan(1)
        self.store.audit("固件召回", f"台区 {zone} 版本 {version} 摘掉 {batches} 个批次")
        return {"zone": zone, "version": version, "batches": batches, "cover": _COVER_NAME[kind], "subsets": subsets}

    def recover_epoch(self, epoch: int, password_a: str, password_b: str) -> dict:
        self.kmc.recover_nonces(1, epoch, password_a, password_b)
        self.store.audit("恢复纪元托管", f"纪元 {epoch} 的托管包已打开")
        return {"ok": True, "epoch": epoch}

    def drop_expired(self) -> dict:
        cohort = self.kmc.cohorts[1]
        self.kmc.drop_expired(1, cohort.epoch)
        self.store.audit("丢弃过期随机数", f"纪元 {cohort.epoch} 之前的随机数已清空，当前纪元保留")
        return {"epoch": cohort.epoch}

    def revoke_gateway(self, zone: int) -> dict:
        self.kmc.revoke_gateway(zone)
        self.store.audit("网关吊销", f"台区 {zone} 的网关槽已作废，管控密钥未轮换")
        return {"zone": zone}

    def reprovision(self, zone: int, local_index: int) -> dict:
        terminal = self._live(zone, local_index)
        self.kmc.reprovision(terminal)
        self.store.audit("重新灌装", f"台区 {zone} 序号 {local_index} 的管理种子按台区管控密钥重新导出，与原先一致")
        return self.lookup(zone, local_index)

    def check_enrollment(self, zone: int, local_index: int) -> dict:
        terminal = self._live(zone, local_index)
        challenge = secrets.token_bytes(16)
        signature = terminal.sign_enrollment(challenge)
        gateway = self.kmc.gateways[zone]
        if self.release is not None:
            gateway.sync_revocation(self.release.revocation, self.kmc.proofs_for_zone(zone))
        if not gateway.verify_enrollment(terminal.tid, local_index, challenge, signature, terminal.epoch):
            raise ProtocolError("接入签名核对失败")
        if not self.kmc.verify_enrollment(terminal.tid, challenge, signature, terminal.epoch):
            raise ProtocolError("接入签名核对失败")
        self.store.audit("接入核验", f"台区 {zone} 序号 {local_index} 的标识签名通过，不改变纪元报文")
        return {"ok": True}

    def note_watch(self) -> dict:
        cohort = self.kmc.cohorts[1]
        zones = [zone_id for zone_id, gateway in self.kmc.gateways.items() if gateway.epoch < cohort.epoch]
        detail = "没有尚未收到报文的台区" if not zones else "尚未收到这一纪元报文的台区 " + "、".join(str(zone) for zone in zones)
        self.store.audit("观察", detail + "。观察名单不是确认失败，不参与验签和是否接受纪元")
        return {"zones": zones}

    def confirm_zone(self, zone: int, withhold: int | None = None) -> dict:
        if self.release is None:
            raise ProtocolError("尚未发布纪元")
        gateway = self.kmc.gateways[zone]
        revoked_before = self._open_revoked_count(zone)
        self._drop_zone_confirmed(zone)
        if gateway.epoch < self.release.epoch:
            gateway.sync(self.release.gateway)
            gateway.sync_revocation(self.release.revocation, self.kmc.proofs_for_zone(zone))
        gateway.reset_acks()
        live = []
        for (zone_id, local), terminal in self.terminals.items():
            if zone_id != zone:
                continue
            record = self.kmc.registry[terminal.tid]
            if record.revoked or record.released or record.destroyed:
                continue
            live.append((local, terminal))
        if withhold is not None and not any(local == withhold for local, _terminal in live):
            raise ProtocolError("扣下的序号不在这个台区的在册终端里")
        present = []
        for local, terminal in live:
            if withhold is not None and local == withhold:
                continue
            if terminal.epoch < self.release.epoch:
                terminal.apply(self.release.terminal)
            gateway.submit_ack(terminal.tid, terminal.ack(), terminal.completion_tag())
            tag, signature = (
                terminal.signed_completion()
                if hasattr(terminal, "signed_completion")
                else sign_completion(terminal)
            )
            gateway.submit_completion(terminal.tid, local, tag, signature)
            present.append(terminal)
        audit_root, audit_ok = gateway.completion_audit()
        if not audit_ok:
            report = gateway.completion_report()
            if self._open_revoked_count(zone) != revoked_before:
                raise ProtocolError("确认失败改变了吊销集")
            self.store.audit(
                "确认",
                f"台区 {zone} 完成签名未通过，完成帧 {len(report)} 字节未接受，已吊销仍为 {revoked_before}",
            )
            return {
                "zone": zone,
                "rejected": True,
                "missing": [],
                "count": 0,
                "bytes": len(report),
                "revoked": revoked_before,
                "audit_root": audit_root.hex(),
                "audit_ok": False,
            }
        if withhold is None:
            report = gateway.completion_report()
            confirmed = self.kmc.accept_report(zone, report)
            self.withheld.pop(zone, None)
            self.store.audit("确认", f"台区 {zone} 完成帧 {len(report)} 字节，已确认 {len(confirmed)} 台")
            return {
                "zone": zone,
                "rejected": False,
                "missing": [],
                "count": len(confirmed),
                "bytes": len(report),
                "revoked": revoked_before,
                "audit_root": audit_root.hex(),
                "audit_ok": audit_ok,
            }
        forged = encode_zall(
            zone,
            gateway.epoch,
            len(live),
            xor_tags([terminal.completion_tag() for terminal in present]),
            gateway.link_key,
        )
        try:
            self.kmc.accept_report(zone, forged)
        except AuthFailed:
            pass
        else:
            raise ProtocolError("扣下终端后完成帧仍被接受")
        if self._open_revoked_count(zone) != revoked_before:
            raise ProtocolError("确认失败改变了吊销集")
        detail = gateway.detail_report()
        named = self.kmc.localize_report(zone, detail)
        missing = [local for local, terminal in live if terminal.tid not in named]
        self.withheld[zone] = withhold
        self.store.audit(
            "确认",
            f"台区 {zone} 完成帧被拒绝，明细缺序号 {'、'.join(str(local) for local in missing)}，已吊销仍为 {revoked_before}",
        )
        return {
            "zone": zone,
            "rejected": True,
            "missing": missing,
            "count": len(named),
            "bytes": len(detail),
            "revoked": revoked_before,
            "audit_root": audit_root.hex(),
            "audit_ok": audit_ok,
        }

    def _open_revoked_count(self, zone: int) -> int:
        return sum(
            1
            for record in self.kmc.registry.values()
            if record.zone == zone and record.revoked and not record.released
        )

    def _drop_zone_confirmed(self, zone: int) -> None:
        confirmed = self.kmc.confirmed.get(1)
        if not confirmed:
            return
        confirmed.difference_update(tid for tid in list(confirmed) if tid >> 16 == zone)

    def audit_tail(self, limit: int = 12) -> list[dict]:
        return self.store.recent_audit(limit)

    def _live(self, zone: int, local_index: int):
        terminal = self.terminals.get((zone, local_index))
        if terminal is None:
            raise ProtocolError("本机没有这台终端")
        return terminal

    def _mirror(self, tid: int) -> None:
        record = self.kmc.registry[tid]
        self.store.upsert_terminal(
            record.tid,
            record.area,
            record.zone,
            record.cohort_id,
            record.leaf,
            record.local_index,
            record.revoked,
            record.released,
            record.destroyed,
        )

    def _checked(self, blob: bytes, parse) -> dict:
        package = parse(blob)
        body = package.raw_body
        return {
            "bytes": len(blob),
            "sm2": self.kmc.hsm.cosign.verify(body, package.sm2_signature()),
        }
