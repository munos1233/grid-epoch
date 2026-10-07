"""地市进程。只保存委托来的密钥和令牌，不打开灌装包，也不装入省级主密钥。"""

from __future__ import annotations

import sys

from .city import CityKMC


def main() -> None:
    line = sys.stdin.readline()
    parts = line.split()
    if len(parts) != 12 or parts[0] != "INIT":
        sys.stdout.write("FAIL\n")
        sys.stdout.flush()
        return
    try:
        area, cohort, slot, n_leaves, span = (int(part) for part in parts[1:6])
        city = CityKMC(
            area,
            cohort,
            slot,
            bytes.fromhex(parts[6]),
            bytes.fromhex(parts[7]),
            bytes.fromhex(parts[8]),
            bytes.fromhex(parts[9]),
            parts[10],
            n_leaves,
            {},
            {},
            span,
        )
        sm9_public = bytes.fromhex(parts[11])
        verify_key = parts[10]
    except Exception:
        sys.stdout.write("FAIL\n")
        sys.stdout.flush()
        return
    sys.stdout.write("READY\n")
    sys.stdout.flush()
    for command in sys.stdin:
        fields = command.split()
        if not fields or fields[0] == "QUIT":
            break
        try:
            if fields[0] == "REGISTER" and len(fields) == 2:
                city.register_zone(int(fields[1]), verify_key, sm9_public)
                sys.stdout.write("OK\n")
            elif fields[0] == "PROVISION" and len(fields) == 4:
                record, blob = city.provision(int(fields[1]), int(fields[2]), fields[3])
                _write_blob(record, blob)
            elif fields[0] == "REVOKE" and len(fields) == 2:
                city.revoke(int(fields[1]))
                sys.stdout.write("OK\n")
            elif fields[0] == "REVOKEBATCH" and len(fields) == 3:
                city.revoke_batch(int(fields[1]), int(fields[2]))
                sys.stdout.write("OK\n")
            elif fields[0] == "TRANSFER" and len(fields) == 5:
                tid = int(fields[1])
                stub = type("_Meter", (), {"tid": tid, "zone_id": tid >> 16})()
                record, blob = city.transfer(stub, int(fields[2]), int(fields[3]), fields[4])
                _write_blob(record, blob)
            elif fields[0] == "DESTROY" and len(fields) == 2:
                city.mark_destroyed(int(fields[1]))
                sys.stdout.write("OK\n")
            else:
                sys.stdout.write("FAIL ProtocolError 地市命令无法识别\n")
        except Exception as exc:
            reason = str(exc).replace("\n", " ").strip()
            sys.stdout.write(f"FAIL {type(exc).__name__} {reason}\n")
        sys.stdout.flush()


def _write_blob(record, blob: bytes) -> None:
    sys.stdout.write(f"BLOB {blob.hex()}\n")
    sys.stdout.write(
        "META"
        f" {record.leaf} {record.tid} {record.zone} {record.local_index}"
        f" {record.firmware_batch} {record.firmware_version}\n"
    )


if __name__ == "__main__":
    main()
