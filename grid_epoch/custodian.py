"""第三份门限分片的保管进程。管道只接受放入，不接收口令，也不把目录交回值班台。"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from .errors import ProtocolError


class ShareSink:
    """值班台持有的只写管道。没有目录，也没有取回方法。"""

    def __init__(self, pipe: _Pipe) -> None:
        self._pipe = pipe

    def put_masters(self, share: bytes) -> None:
        self._ok(f"PUT masters {share.hex()}")

    def put_nonce(self, epoch: int, share: bytes) -> None:
        self._ok(f"PUT nonce {epoch} {share.hex()}")

    def close(self) -> None:
        pipe = getattr(self, "_pipe", None)
        if pipe is not None:
            pipe.close()
            self._pipe = None

    def _ok(self, line: str) -> None:
        self._pipe.send(line)
        if self._pipe.read() != "OK":
            raise ProtocolError("保管进程没有收下分片")


def open_share_sink() -> tuple[ShareSink, Path]:
    """打开只写管道，并把保管进程自己选的目录交给调用方。"""
    pipe = _Pipe([sys.executable, "-m", "grid_epoch.custodian"])
    try:
        pipe.send("INIT")
        if pipe.read() != "READY":
            raise ProtocolError("保管进程没有就绪")
        kind, path = pipe.read_error().split(" ", 1)
        if kind != "DIR":
            raise ProtocolError("保管进程没有就绪")
        return ShareSink(pipe), Path(path)
    except Exception:
        pipe.close()
        raise


def main() -> None:
    directory = Path(tempfile.mkdtemp(prefix="grid-custodian-"))
    for command in sys.stdin:
        fields = command.split()
        if not fields or fields[0] == "QUIT":
            break
        try:
            if fields[0] == "INIT" and len(fields) == 1:
                sys.stdout.write("READY\n")
                sys.stdout.flush()
                sys.stderr.write(f"DIR {directory}\n")
                sys.stderr.flush()
                continue
            if fields[0] == "PUT" and fields[1] == "masters" and len(fields) == 3:
                (directory / "share_offline.bin").write_bytes(bytes.fromhex(fields[2]))
                sys.stdout.write("OK\n")
            elif fields[0] == "PUT" and fields[1] == "nonce" and len(fields) == 4:
                (directory / f"nonce_{int(fields[2])}.bin").write_bytes(bytes.fromhex(fields[3]))
                sys.stdout.write("OK\n")
            else:
                sys.stdout.write("FAIL\n")
        except Exception:
            sys.stdout.write("FAIL\n")
        sys.stdout.flush()


class _Pipe:
    def __init__(self, command: list[str]) -> None:
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def send(self, line: str) -> None:
        if self.proc.stdin is None:
            raise ProtocolError("保管进程管道已经关闭")
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def read(self) -> str:
        if self.proc.stdout is None:
            raise ProtocolError("保管进程管道已经关闭")
        line = self.proc.stdout.readline()
        if not line:
            raise ProtocolError("保管进程已退出")
        return line.strip()

    def read_error(self) -> str:
        if self.proc.stderr is None:
            raise ProtocolError("保管进程管道已经关闭")
        line = self.proc.stderr.readline()
        if not line:
            raise ProtocolError("保管进程已退出")
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
            if self.proc.stderr is not None:
                self.proc.stderr.close()


if __name__ == "__main__":
    main()
