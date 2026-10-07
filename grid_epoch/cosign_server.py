"""协同签名的服务端进程。只保存 d2，经管道完成 k2/s2。"""

from __future__ import annotations

import secrets
import sys

from gmssl import sm2

from .cosign import _add


def main() -> None:
    table = sm2.default_ecc_table
    n = int(table["n"], 16)
    curve = sm2.CryptSM2(public_key="00" * 64, private_key="00" * 32)
    d2 = secrets.randbelow(n - 1) + 1
    w2 = curve._kg(pow(d2, -1, n), table["g"])
    sys.stdout.write(f"READY {w2}\n")
    sys.stdout.flush()
    for line in sys.stdin:
        parts = line.strip().split()
        if len(parts) != 3 or parts[0] != "SIGN":
            sys.stdout.write("FAIL\n")
            sys.stdout.flush()
            continue
        try:
            e = int(parts[1], 16)
            q1 = parts[2]
        except ValueError:
            sys.stdout.write("FAIL\n")
            sys.stdout.flush()
            continue
        answer = _partial(curve, table["g"], n, d2, e, q1)
        if answer is None:
            sys.stdout.write("FAIL\n")
        else:
            point, s2 = answer
            sys.stdout.write(f"PART {point} {s2:064x}\n")
        sys.stdout.flush()


def _partial(curve, g: str, n: int, d2: int, e: int, q1: str):
    k2 = secrets.randbelow(n - 1) + 1
    point = _add(curve, curve._kg(k2, g), q1)
    if point is None:
        return None
    x1 = int(point[: curve.para_len], 16)
    r = (e + x1) % n
    if r == 0 or (r + k2) % n == 0:
        return None
    s2 = (d2 * ((r + k2) % n)) % n
    if s2 == 0:
        return None
    return point, s2


if __name__ == "__main__":
    main()
