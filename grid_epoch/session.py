"""演示和值班台的灌装会话。地市进程封装，产线进程持有设备私钥。"""

from __future__ import annotations

import subprocess
import sys

from .errors import AuthFailed, EpochRejected, ProtocolError, TerminalRevoked


_FAILURES = {
    "EpochRejected": EpochRejected,
    "TerminalRevoked": TerminalRevoked,
    "ProtocolError": ProtocolError,
    "AuthFailed": AuthFailed,
}


def _stated_failure(line: str, fallback: str) -> ProtocolError:
    parts = line.split(" ", 2)
    if len(parts) < 3 or parts[0] != "FAIL" or not parts[2]:
        return ProtocolError(fallback)
    return _FAILURES.get(parts[1], ProtocolError)(parts[2])


class ProvisionSession:
    def __init__(self, kmc, cohort_id: int) -> None:
        self.kmc = kmc
        self.cohort_id = cohort_id
        city = kmc.cities[cohort_id]
        init = " ".join(
            [
                "INIT",
                str(city.area),
                str(city.cohort_id),
                str(city.slot),
                str(city.cohort.terminals.n),
                str(city.cohort.span),
                city.city_mgmt.hex(),
                city.city_biz.hex(),
                city.broadcast.hex(),
                city.token.hex(),
                city.verify_key,
                kmc.hsm.sm9_public.hex(),
            ]
        )
        self.city = _Pipe([sys.executable, "-m", "grid_epoch.city_server"])
        self.factory = _Pipe([sys.executable, "-m", "grid_epoch.factory"])
        self.city.send(init)
        if self.city.read() != "READY":
            self.close()
            raise ProtocolError("地市进程没有就绪")

    def register(self, zone_id: int) -> None:
        self.city.send(f"REGISTER {zone_id}")
        if self.city.read() != "OK":
            raise ProtocolError("地市进程没有注册这个台区")

    def enroll(self, zone_id: int, local_index: int):
        public = self._new_device()
        identity = self.kmc.hsm.seal_user_key(public, self.kmc.area, zone_id, local_index)
        self.city.send(f"PROVISION {zone_id} {local_index} {public}")
        blob, meta = self._read_provision()
        record = self.kmc.cities[self.cohort_id].adopt_terminal(
            zone_id,
            local_index,
            meta["leaf"],
            public,
            meta["batch"],
            meta["version"],
        )
        if record.tid != meta["tid"]:
            raise ProtocolError("叶子号和地市进程不一致")
        self._open_factory(public, blob, identity, record)
        return RemoteTerminal(self, record.tid, zone_id, record.leaf, self.kmc)

    def drop(self, tid: int) -> None:
        self.factory.send(f"DROP {tid}")
        if self.factory.read() != "OK":
            raise ProtocolError("产线没有丢掉这台终端的签名私钥")

    def revoke(self, tid: int) -> None:
        self.city.send(f"REVOKE {tid}")
        if self.city.read() != "OK":
            raise ProtocolError("地市进程没有吊销这台终端")
        self.kmc.revoke(tid)

    def revoke_batch(self, zone_id: int, batch_index: int) -> None:
        self.city.send(f"REVOKEBATCH {zone_id} {batch_index}")
        if self.city.read() != "OK":
            raise ProtocolError("地市进程没有摘掉这个批次")
        self.kmc.recall_firmware_batch(zone_id, batch_index)

    def mark_destroyed(self, tid: int) -> None:
        self.city.send(f"DESTROY {tid}")
        reply = self.city.read()
        if reply != "OK":
            raise _stated_failure(reply, "地市进程没有记下销毁")

    def transfer(self, terminal, new_zone: int, new_local: int):
        if self.kmc.registry[terminal.tid].destroyed:
            raise ProtocolError("终端已销毁")
        if new_zone not in self.kmc.gateways:
            self.kmc.register_zone(new_zone, self.cohort_id)
            self.register(new_zone)
        public = self.kmc.registry[terminal.tid].device_pub
        identity = self.kmc.hsm.seal_user_key(public, self.kmc.area, new_zone, new_local)
        self.city.send(f"TRANSFER {terminal.tid} {new_zone} {new_local} {public}")
        blob, meta = self._read_provision()
        self.kmc.revoke(terminal.tid)
        record = self.kmc.cities[self.cohort_id].adopt_terminal(
            new_zone,
            new_local,
            meta["leaf"],
            public,
            meta["batch"],
            meta["version"],
        )
        self._open_factory(public, blob, identity, record)
        return RemoteTerminal(self, record.tid, new_zone, record.leaf, self.kmc)

    def close(self) -> None:
        for pipe in (getattr(self, "city", None), getattr(self, "factory", None)):
            if pipe is not None:
                pipe.close()

    def _new_device(self) -> str:
        self.factory.send("NEW")
        kind, public = self.factory.read().split()
        if kind != "PUB":
            raise ProtocolError("产线没有交出设备公钥")
        return public

    def _read_provision(self) -> tuple[str, dict]:
        first = self.city.read()
        if not first.startswith("BLOB "):
            raise _stated_failure(first, "地市进程没有返回封装")
        blob_line = first.split()
        meta_line = self.city.read().split()
        if len(blob_line) != 2 or len(meta_line) != 7 or meta_line[0] != "META":
            raise ProtocolError("地市进程没有返回封装")
        meta = {
            "leaf": int(meta_line[1]),
            "tid": int(meta_line[2]),
            "zone": int(meta_line[3]),
            "local": int(meta_line[4]),
            "batch": int(meta_line[5]),
            "version": int(meta_line[6]),
        }
        return blob_line[1], meta

    def _open_factory(self, public: str, blob: str, identity: bytes, record) -> None:
        cohort = self.kmc.cohorts[self.cohort_id]
        self.factory.send(
            "OPEN"
            f" {public} {blob} {identity.hex()}"
            f" {record.area} {record.zone} {record.tid} {record.leaf} {record.cohort_id}"
            f" {cohort.epoch} {cohort.last_timestamp} {cohort.terminals.n}"
            f" {cohort.current_biz().hex()} {cohort.current_auth().hex()} {self.kmc.hsm.public_key}"
        )
        opened = self.factory.read()
        if not opened.startswith("OPEN "):
            raise _stated_failure(opened, "产线没有打开灌装包")


class RemoteTerminal:
    """省级进程里的终端代理。种子和设备私钥留在产线进程。"""

    def __init__(self, session: ProvisionSession, tid: int, zone_id: int, leaf: int, kmc) -> None:
        self.session = session
        self.tid = tid
        self.zone_id = zone_id
        self.leaf = leaf
        self.kmc = kmc
        self.area = kmc.area
        self.epoch = kmc.cohorts[session.cohort_id].epoch

    def apply(self, blob: bytes) -> None:
        reply = self._ask(f"APPLY {self.tid} {blob.hex()}")
        kind, epoch = reply.split()
        if kind != "EPOCH":
            raise ProtocolError("产线没有接受纪元报文")
        self.epoch = int(epoch)

    def prove(self, challenge: bytes) -> bytes:
        reply = self._ask(f"PROOF {self.tid} {challenge.hex()}")
        kind, proof = reply.split()
        if kind != "PROOF":
            raise ProtocolError("产线没有返回认证证明")
        return bytes.fromhex(proof)

    def seal_telemetry(self, plaintext: bytes) -> bytes:
        reply = self._ask(f"TELEMETRY {self.tid} {plaintext.hex()}")
        kind, record = reply.split()
        if kind != "REC":
            raise ProtocolError("产线没有返回上行报文")
        return bytes.fromhex(record)

    def ack(self) -> bytes:
        reply = self._ask(f"ACK {self.tid}")
        kind, ack = reply.split()
        if kind != "ACK":
            raise ProtocolError("产线没有返回确认")
        return bytes.fromhex(ack)

    def completion_tag(self) -> bytes:
        return self.signed_completion()[0]

    def signed_completion(self) -> tuple[bytes, bytes]:
        reply = self._ask(f"TAG {self.tid}")
        kind, tag, signature = reply.split()
        if kind != "TAG":
            raise ProtocolError("产线没有返回完成签名")
        return bytes.fromhex(tag), bytes.fromhex(signature)

    def sign_enrollment(self, challenge: bytes) -> bytes:
        reply = self._ask(f"ENROLL {self.tid} {challenge.hex()}")
        kind, signature = reply.split()
        if kind != "SIG":
            raise ProtocolError("产线没有返回接入签名")
        return bytes.fromhex(signature)

    def device_keys(self) -> tuple[bytes, bytes]:
        expected = self.kmc.device_keys(self.tid)
        reply = self._ask(f"MATCH {self.tid} {expected[0].hex()} {expected[1].hex()}")
        if reply != "MATCH":
            raise ProtocolError("终端密钥与主站不一致")
        return expected

    def _ask(self, line: str) -> str:
        self.session.factory.send(line)
        reply = self.session.factory.read()
        if reply.startswith("FAIL "):
            parts = reply.split(" ", 2)
            kind = parts[1] if len(parts) > 1 else "ProtocolError"
            message = parts[2] if len(parts) > 2 else "产线拒绝了这次操作"
            raise _FAILURES.get(kind, ProtocolError)(message)
        return reply


class _Pipe:
    def __init__(self, command: list[str]) -> None:
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )

    def send(self, line: str) -> None:
        if self.proc.stdin is None:
            raise ProtocolError("进程管道已经关闭")
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def read(self) -> str:
        if self.proc.stdout is None:
            raise ProtocolError("进程管道已经关闭")
        line = self.proc.stdout.readline()
        if not line:
            raise ProtocolError("对端进程已退出")
        return line.strip()

    def close(self) -> None:
        try:
            if self.proc.poll() is None and self.proc.stdin is not None:
                self.proc.stdin.write("QUIT\n")
                self.proc.stdin.flush()
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
            self.proc.wait(timeout=10)
        finally:
            if self.proc.stdin is not None:
                self.proc.stdin.close()
            if self.proc.stdout is not None:
                self.proc.stdout.close()
