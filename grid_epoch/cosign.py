"""两方 SM2 协同签名。调用方保存 d1，服务进程保存 d2。

公钥按 P = [d2^{-1}][d1^{-1}]G − G 生成，输出的 r‖s 能被普通 SM2 验签接受。
交互是 Q1 = [k1]W1，(x1, y1) = [k2]G + Q1，s2 = d2(r + k2)，s = k1 + d1·s2 − r。
任何一方对象都不含另一份分片，也不拼出 d。

没有逐条核对 GM/T 0144-2025 正文，因此这里不标成该标准。
双人口令封装主密钥是另一件事，见 custody.py。
"""

from __future__ import annotations

import atexit
import os
import subprocess
import sys
import threading
from pathlib import Path

from gmssl import sm2

from .sm2util import verifier


class ClientShare:
    """调用方分片。没有服务端的 s2 时给不出可验证的 SM2 签名。"""

    def __init__(self, d1: int, w1: str) -> None:
        self._d1 = d1
        self.w1 = w1

    def finish(self, k1: int, r: int, s2: int, n: int) -> int:
        return (k1 + self._d1 * s2 - r) % n


class ServerShare:
    """保留给直接持有 d2 的计算。生产路径把这一份放进独立进程。"""

    def __init__(self, d2: int) -> None:
        self._d2 = d2

    def partial(self, r: int, k2: int, n: int) -> int:
        return (self._d2 * ((r + k2) % n)) % n


class CollaborativeSM2:
    def __init__(self) -> None:
        table = sm2.default_ecc_table
        n = int(table["n"], 16)
        curve = sm2.CryptSM2(public_key="00" * 64, private_key="00" * 32)
        g = table["g"]
        d1 = secrets_d(n)
        self._proc = _spawn()
        ready = self._proc.stdout.readline().strip().split()
        if len(ready) != 2 or ready[0] != "READY":
            self.close()
            raise RuntimeError("协同签名进程没有就绪")
        w2 = ready[1]
        w1 = curve._kg(pow(d1, -1, n), w2)
        public = _sub(curve, w1, g)
        if not public:
            self.close()
            raise RuntimeError("协同公钥生成失败")
        self.public_key = public
        self.client = ClientShare(d1, w1)
        self._curve = curve
        self._n = n
        self._g = g
        self._verify = verifier(public)
        self._lock = threading.Lock()
        atexit.register(self.close)

    def sign(self, data: bytes) -> bytes:
        digest = sm2.CryptSM2(public_key=self.public_key, private_key="00" * 32)
        e = int(digest._sm3_z(data), 16)
        for _ in range(16):
            signature = self._attempt(e)
            if signature is not None and self._verify(data, signature):
                return signature
        raise RuntimeError("协同签名失败")

    def verify(self, data: bytes, signature: bytes) -> bool:
        return self._verify(data, signature)

    def close(self) -> None:
        proc = getattr(self, "_proc", None)
        if proc is None or proc.poll() is not None:
            self._proc = None
            return
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is None:
                continue
            try:
                stream.close()
            except Exception:
                pass
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        self._proc = None

    def _attempt(self, e: int) -> bytes | None:
        n = self._n
        k1 = secrets_d(n)
        q1 = self._curve._kg(k1, self.client.w1)
        with self._lock:
            if self._proc is None or self._proc.poll() is not None:
                raise RuntimeError("协同签名进程已退出")
            self._proc.stdin.write(f"SIGN {e:x} {q1}\n")
            self._proc.stdin.flush()
            line = self._proc.stdout.readline().strip().split()
        if len(line) != 3 or line[0] != "PART":
            return None
        point = line[1]
        s2 = int(line[2], 16)
        x1 = int(point[: self._curve.para_len], 16)
        r = (e + x1) % n
        s = self.client.finish(k1, r, s2, n)
        if r == 0 or s == 0 or (r + s) % n == 0:
            return None
        return bytes.fromhex(f"{r:064x}{s:064x}")


def secrets_d(n: int) -> int:
    import secrets

    return secrets.randbelow(n - 1) + 1


def _spawn() -> subprocess.Popen:
    root = str(Path(__file__).resolve().parent.parent)
    env = os.environ.copy()
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.Popen(
        [sys.executable, "-m", "grid_epoch.cosign_server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )


def _add(curve: sm2.CryptSM2, left: str, right: str) -> str | None:
    added = curve._add_point(left, right)
    if added is None:
        return None
    return curve._convert_jacb_to_nor(added)


def _sub(curve: sm2.CryptSM2, point: str, other: str) -> str | None:
    prime = int(curve.ecc_table["p"], 16)
    width = curve.para_len
    x = other[:width]
    y = (prime - int(other[width:], 16)) % prime
    return _add(curve, point, x + f"{y:0{width}x}")
