"""编译国密原语动态库。"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
LIB = Path(__file__).resolve().parent / "libgridcrypto.dylib"
SOURCES = [NATIVE / "sm3.c", NATIVE / "sm4.c", NATIVE / "batch.c"]


def build(out: Path = LIB) -> Path:
    cmd = [
        "clang",
        "-O3",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-pthread",
        "-dynamiclib",
        "-o",
        str(out),
        *[str(p) for p in SOURCES],
    ]
    subprocess.check_call(cmd)
    return out


def ensure(out: Path = LIB) -> Path:
    if out.exists() and all(out.stat().st_mtime >= src.stat().st_mtime for src in SOURCES):
        return out
    return build(out)
