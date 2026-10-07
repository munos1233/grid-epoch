"""主站和终端分属两个进程。主站只把报文写进目录。"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from .errors import EpochRejected, TerminalRevoked
from .kmc import ProvincialKMC
from .session import ProvisionSession
from .terminal import Terminal
from .timekey import TimeFrontier


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="grid-epoch-") as directory:
        work = Path(directory)
        kmc = ProvincialKMC(area=330100)
        kmc.arm_escrow("甲", "乙")
        kmc.create_cohort(1, 16)
        session = ProvisionSession(kmc, 1)
        try:
            kmc.register_zone(7, 1)
            session.register(7)
            terminal = session.enroll(7, 1)
            neighbor = session.enroll(7, 3)
            kmc.publish(1)
            second = kmc.publish(1)
            (work / "epoch2.bin").write_bytes(second.terminal)
            terminal.apply(second.terminal)
            epoch = terminal.epoch
            print(f"步骤1 漏掉纪元 1 后进入纪元 {epoch}")
            if epoch != 2:
                raise SystemExit("终端没有进入纪元 2")
            neighbor.apply(second.terminal)

            kmc.revoke(terminal.tid)
            revoked = kmc.publish(1)
            (work / "revoked.bin").write_bytes(revoked.terminal)
            failure = _apply_label(terminal, revoked.terminal)
            print(f"步骤2 吊销后 {failure}")
            if failure != "TerminalRevoked":
                raise SystemExit("吊销后仍然解得开")

            newbie = session.enroll(7, 2)
            opened = kmc.publish(1)
            (work / "fresh.bin").write_bytes(opened.terminal)
            new_epoch = _apply_epoch(newbie, opened.terminal)
            old_failure = _apply_label(terminal, opened.terminal)
            neighbor_epoch = _apply_epoch(neighbor, opened.terminal)
            print(f"步骤3 新表进入纪元 {new_epoch}，旧表 {old_failure}，漏收过纪元的邻表进入 {neighbor_epoch}")
            if new_epoch != opened.epoch or old_failure == "ok" or neighbor_epoch != opened.epoch:
                raise SystemExit("换表后的终端行为不对")
        finally:
            session.close()


def _apply_epoch(terminal, packet: bytes) -> int:
    terminal.apply(packet)
    return terminal.epoch


def _apply_label(terminal, packet: bytes) -> str:
    try:
        terminal.apply(packet)
    except TerminalRevoked:
        return "TerminalRevoked"
    except EpochRejected:
        return "EpochRejected"
    return "ok"


def _child(mode: str, state: Path, packet: Path) -> str:
    completed = subprocess.run(
        [sys.executable, "-m", "grid_epoch.split_demo", mode, str(state), str(packet)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.stderr.strip() or completed.stdout.strip() or "子进程失败")
    return completed.stdout.strip()


def _write_state(path: Path, terminal, kmc: ProvincialKMC) -> None:
    frontier = terminal.biz_frontier
    payload = {
        "tid": terminal.tid,
        "area": terminal.area,
        "zone_id": terminal.zone_id,
        "cohort_id": terminal.cohort_id,
        "leaf": terminal.leaf,
        "seed_mgmt": terminal.seed_mgmt.hex(),
        "epoch": terminal.epoch,
        "nonce": terminal.nonce.hex(),
        "auth_nonce": terminal.auth_nonce.hex(),
        "last_timestamp": terminal.last_timestamp,
        "path_order": terminal.path_order,
        "path_keys": {str(key): value.hex() for key, value in terminal.path_keys.items()},
        "sd_stubs": {f"{root}:{hanging}": value.hex() for (root, hanging), value in terminal.sd_stubs.items()},
        "full_bases": {str(key): value.hex() for key, value in terminal.full_bases.items()},
        "sd_secret": terminal.sd_secret.hex(),
        "public_key": kmc.hsm.public_key,
        "frontier_index": frontier.index,
        "frontier_era": frontier.era,
        "frontier": [
            {"start": start, "span": span, "key": bytes(key).hex()}
            for start, span, key in frontier.nodes
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _read_state(path: Path) -> Terminal:
    data = json.loads(path.read_text(encoding="utf-8"))
    terminal = Terminal(
        tid=data["tid"],
        area=data["area"],
        zone_id=data["zone_id"],
        cohort_id=data["cohort_id"],
        leaf=data["leaf"],
        seed_mgmt=bytes.fromhex(data["seed_mgmt"]),
        seed_biz=bytes(32),
        path_order=data["path_order"],
        path_keys={int(key): bytes.fromhex(value) for key, value in data["path_keys"].items()},
        sd_stubs={
            tuple(int(part) for part in key.split(":")): bytes.fromhex(value)
            for key, value in data.get("sd_stubs", {}).items()
        },
        full_bases={int(key): bytes.fromhex(value) for key, value in data.get("full_bases", {}).items()},
        sd_secret=bytes.fromhex(data["sd_secret"]) if data.get("sd_secret") else None,
        epoch=0,
        nonce=bytes.fromhex(data["nonce"]),
        auth_nonce=bytes.fromhex(data.get("auth_nonce", data["nonce"])),
        last_timestamp=data["last_timestamp"],
        public_key=data["public_key"],
    )
    frontier = TimeFrontier(bytes(32))
    frontier.nodes = [
        (item["start"], item["span"], bytearray(bytes.fromhex(item["key"])))
        for item in data["frontier"]
    ]
    frontier.index = data["frontier_index"]
    frontier.era = data.get("frontier_era", 0)
    terminal.biz_frontier = frontier
    terminal.epoch = data["epoch"]
    terminal.nonce = bytes.fromhex(data["nonce"])
    return terminal


def _worker_checked(argv: list[str]) -> None:
    mode, state_path, packet_path = argv
    terminal = _read_state(Path(state_path))
    packet = Path(packet_path).read_bytes()
    try:
        terminal.apply(packet)
    except TerminalRevoked:
        print("TerminalRevoked")
        return
    except EpochRejected:
        print("EpochRejected")
        return
    if mode == "reject":
        print("ok")
        return
    data = json.loads(Path(state_path).read_text(encoding="utf-8"))
    data["epoch"] = terminal.epoch
    data["nonce"] = terminal.nonce.hex()
    data["auth_nonce"] = terminal.auth_nonce.hex()
    data["frontier_era"] = terminal.biz_frontier.era
    data["last_timestamp"] = terminal.last_timestamp
    data["path_keys"] = {str(key): value.hex() for key, value in terminal.path_keys.items()}
    frontier = terminal.biz_frontier
    data["frontier_index"] = frontier.index
    data["frontier"] = [
        {"start": start, "span": span, "key": bytes(key).hex()}
        for start, span, key in frontier.nodes
    ]
    Path(state_path).write_text(json.dumps(data), encoding="utf-8")
    print(terminal.epoch)


if __name__ == "__main__":
    if len(sys.argv) == 4:
        _worker_checked(sys.argv[1:])
    else:
        main()
