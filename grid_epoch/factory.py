"""产线进程。设备私钥在这里生成，种子封装也只在这里打开。"""

from __future__ import annotations

import sys

from .crypto import sm3
from .device import DeviceKey
from .errors import AuthFailed, EpochRejected, ProtocolError, TerminalRevoked
from .kmc import TerminalRecord
from .terminal import terminal_from_provision


def main() -> None:
    devices: dict[str, DeviceKey] = {}
    terminals: dict[int, object] = {}
    dropped: set[int] = set()
    for command in sys.stdin:
        fields = command.split()
        if not fields or fields[0] == "QUIT":
            break
        try:
            if fields[0] == "NEW" and len(fields) == 1:
                device = DeviceKey()
                devices[device.public_key] = device
                sys.stdout.write(f"PUB {device.public_key}\n")
            elif fields[0] == "OPEN" and len(fields) == 15:
                terminal = _open_terminal(devices, fields)
                terminals[terminal.tid] = terminal
                sys.stdout.write(f"OPEN {sm3(terminal.provision_blob).hex()}\n")
            elif fields[0] == "APPLY" and len(fields) == 3:
                terminal = _require(terminals, dropped, fields[1])
                terminal.apply(bytes.fromhex(fields[2]))
                sys.stdout.write(f"EPOCH {terminal.epoch}\n")
            elif fields[0] == "PROOF" and len(fields) == 3:
                terminal = _require(terminals, dropped, fields[1])
                sys.stdout.write(f"PROOF {terminal.prove(bytes.fromhex(fields[2])).hex()}\n")
            elif fields[0] == "TELEMETRY" and len(fields) == 3:
                terminal = _require(terminals, dropped, fields[1])
                sys.stdout.write(f"REC {terminal.seal_telemetry(bytes.fromhex(fields[2])).hex()}\n")
            elif fields[0] == "ACK" and len(fields) == 2:
                terminal = _require(terminals, dropped, fields[1])
                sys.stdout.write(f"ACK {terminal.ack().hex()}\n")
            elif fields[0] == "DROP" and len(fields) == 2:
                _drop_terminal(devices, terminals, dropped, fields[1])
                sys.stdout.write("OK\n")
            elif fields[0] == "TAG" and len(fields) == 2:
                from .auditproof import sign_completion

                terminal = _require(terminals, dropped, fields[1])
                if terminal.sm9_user is None:
                    raise ProtocolError("终端没有接入签名密钥")
                tag, signature = sign_completion(terminal)
                sys.stdout.write(f"TAG {tag.hex()} {signature.hex()}\n")
            elif fields[0] == "ENROLL" and len(fields) == 3:
                terminal = _require(terminals, dropped, fields[1])
                sys.stdout.write(f"SIG {terminal.sign_enrollment(bytes.fromhex(fields[2])).hex()}\n")
            elif fields[0] == "MATCH" and len(fields) == 4:
                terminal = _require(terminals, dropped, fields[1])
                auth, biz = terminal.device_keys()
                same = auth == bytes.fromhex(fields[2]) and biz == bytes.fromhex(fields[3])
                sys.stdout.write("MATCH\n" if same else "DIFF\n")
            else:
                sys.stdout.write("FAIL ProtocolError 产线命令无法识别\n")
        except (EpochRejected, TerminalRevoked, ProtocolError, AuthFailed) as exc:
            sys.stdout.write(f"FAIL {type(exc).__name__} {exc}\n")
        except Exception:
            sys.stdout.write("FAIL ProtocolError 产线没有完成这次操作\n")
        sys.stdout.flush()


def _require(terminals: dict[int, object], dropped: set[int], raw: str):
    tid = int(raw)
    terminal = terminals.get(tid)
    if terminal is None:
        if tid in dropped:
            raise ProtocolError("终端已销毁")
        raise ProtocolError("产线没有这台终端")
    return terminal


def _drop_terminal(devices: dict[str, DeviceKey], terminals: dict[int, object], dropped: set[int], raw: str) -> None:
    terminal = _require(terminals, dropped, raw)
    public = terminal.device.public_key if terminal.device is not None else None
    shared = public is not None and any(
        item is not terminal and item.device is not None and item.device.public_key == public
        for item in terminals.values()
    )
    terminal.wipe(release_device=not shared)
    dropped.add(terminal.tid)
    del terminals[terminal.tid]
    if public is None or shared:
        return
    leftover = devices.pop(public, None)
    if leftover is not None:
        leftover.discard()


def _open_terminal(devices: dict[str, DeviceKey], fields: list[str]):
    device = devices.get(fields[1])
    if device is None:
        raise ProtocolError("产线没有这把设备密钥")
    area, zone, tid, leaf, cohort, epoch, stamp, tree_n = (int(part) for part in fields[4:12])
    record = TerminalRecord(
        tid=tid,
        area=area,
        zone=zone,
        cohort_id=cohort,
        leaf=leaf,
        local_index=tid & 0xFFFF,
        device_pub=device.public_key,
    )
    cohort_view = _CohortView(epoch, bytes.fromhex(fields[12]), bytes.fromhex(fields[13]), stamp, tree_n)
    return terminal_from_provision(
        device,
        bytes.fromhex(fields[2]),
        bytes.fromhex(fields[3]),
        record,
        cohort_view,
        fields[14],
    )


class _CohortView:
    def __init__(self, epoch: int, biz: bytes, auth: bytes, stamp: int, tree_n: int) -> None:
        self.epoch = epoch
        self.last_timestamp = stamp
        self._biz = biz
        self._auth = auth
        self.terminals = type("_Size", (), {"n": tree_n})()

    def current_biz(self) -> bytes:
        return self._biz

    def current_auth(self) -> bytes:
        return self._auth


if __name__ == "__main__":
    main()
