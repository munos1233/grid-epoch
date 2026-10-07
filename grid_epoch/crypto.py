"""SM3 / SM4 / HMAC-SM3 的 Python 接口，热路径在 native 库中。"""

from __future__ import annotations

import ctypes
from functools import lru_cache

from .build import ensure


class _SeedTable(ctypes.Structure):
    _fields_ = [
        ("mgmt", ctypes.POINTER(ctypes.c_uint8)),
        ("biz", ctypes.POINTER(ctypes.c_uint8)),
        ("count", ctypes.c_uint64),
    ]


@lru_cache(maxsize=1)
def load():
    lib = ctypes.CDLL(str(ensure()))
    lib.ge_selftest.restype = ctypes.c_int
    if lib.ge_selftest() != 0:
        raise RuntimeError("SM3/SM4 自检失败，拒绝继续运行")

    lib.ge_sm3.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    lib.ge_sm3_kdf.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t
    ]
    lib.ge_sm3_kdf.restype = ctypes.c_int
    lib.ge_sm4_encrypt_block.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.ge_hmac_sm3.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p
    ]
    lib.ge_seed_pair.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p,
    ]
    lib.ge_seed_pair.restype = ctypes.c_int
    lib.ge_stream_topology.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int,
        ctypes.c_void_p, ctypes.c_void_p,
    ]
    lib.ge_stream_topology.restype = ctypes.c_int
    lib.ge_provision.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int,
    ]
    lib.ge_provision.restype = ctypes.POINTER(_SeedTable)
    lib.ge_seed_table_free.argtypes = [ctypes.POINTER(_SeedTable)]
    lib.ge_parallel_update.argtypes = [
        ctypes.POINTER(_SeedTable), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
    ]
    lib.ge_parallel_update.restype = ctypes.c_int
    lib.ge_stream_ack.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_int, ctypes.c_void_p,
    ]
    lib.ge_stream_ack.restype = ctypes.c_int
    lib.ge_aead_open.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.ge_aead_open.restype = ctypes.c_int
    return lib


def _in(data: bytes):
    return ctypes.create_string_buffer(data)


def sm3(data: bytes) -> bytes:
    out = (ctypes.c_uint8 * 32)()
    load().ge_sm3(_in(data), len(data), out)
    return bytes(out)


def kdf(z: bytes, klen: int) -> bytes:
    if klen < 0:
        raise ValueError("klen 不能为负")
    out = (ctypes.c_uint8 * klen)() if klen else (ctypes.c_uint8 * 1)()
    rc = load().ge_sm3_kdf(_in(z), len(z), out, klen)
    if rc != 0:
        raise ValueError("KDF 输入过长")
    return bytes(out[:klen])


def sm4_block(key: bytes, block: bytes) -> bytes:
    if len(key) != 16 or len(block) != 16:
        raise ValueError("SM4 分组与密钥均为 16 字节")
    out = (ctypes.c_uint8 * 16)()
    load().ge_sm4_encrypt_block(_in(key), _in(block), out)
    return bytes(out)


def hmac_sm3(key: bytes, msg: bytes) -> bytes:
    out = (ctypes.c_uint8 * 32)()
    load().ge_hmac_sm3(_in(key), len(key), _in(msg), len(msg), out)
    return bytes(out)


def seed_pair_native(
    mk_mgmt: bytes, mk_biz: bytes, area: int, cohort: int, county: int, zone: int, tid: int
) -> tuple[bytes, bytes]:
    mgmt = (ctypes.c_uint8 * 32)()
    biz = (ctypes.c_uint8 * 32)()
    rc = load().ge_seed_pair(_in(mk_mgmt), _in(mk_biz), area, cohort, county, zone, tid, mgmt, biz)
    if rc != 0:
        raise RuntimeError("种子派生失败")
    return bytes(mgmt), bytes(biz)


def stream_topology(
    mk_mgmt: bytes,
    mk_biz: bytes,
    area: int,
    cohort: int,
    zone_begin: int,
    n_zones: int,
    per_zone: int,
    county_width: int,
    threads: int,
) -> tuple[bytes, bytes]:
    xor_mgmt = (ctypes.c_uint8 * 32)()
    xor_biz = (ctypes.c_uint8 * 32)()
    rc = load().ge_stream_topology(
        _in(mk_mgmt),
        _in(mk_biz),
        area,
        cohort,
        zone_begin,
        n_zones,
        per_zone,
        county_width,
        threads,
        xor_mgmt,
        xor_biz,
    )
    if rc != 0:
        raise RuntimeError(f"批量派生失败 rc={rc}")
    return bytes(xor_mgmt), bytes(xor_biz)


def provision_table(
    mk_mgmt: bytes,
    mk_biz: bytes,
    area: int,
    cohort: int,
    zone_begin: int,
    n_zones: int,
    per_zone: int,
    county_width: int,
    threads: int,
):
    table = load().ge_provision(
        _in(mk_mgmt),
        _in(mk_biz),
        area,
        cohort,
        zone_begin,
        n_zones,
        per_zone,
        county_width,
        threads,
    )
    if not table:
        raise MemoryError("无法为终端种子分配内存")
    return table


def free_table(table) -> None:
    load().ge_seed_table_free(table)


def stream_ack(
    mk_biz: bytes,
    area: int,
    cohort: int,
    zone_begin: int,
    n_zones: int,
    per_zone: int,
    county_width: int,
    epoch: int,
    nonce: bytes,
    threads: int,
) -> bytes:
    if len(nonce) != 16:
        raise ValueError("纪元随机数必须是 16 字节")
    folded = (ctypes.c_uint8 * 16)()
    rc = load().ge_stream_ack(
        _in(mk_biz),
        area,
        cohort,
        zone_begin,
        n_zones,
        per_zone,
        county_width,
        epoch,
        _in(nonce),
        threads,
        folded,
    )
    if rc != 0:
        raise RuntimeError(f"批量确认失败 rc={rc}")
    return bytes(folded)


def parallel_update(table, root_key: bytes, sealed: bytes, threads: int):
    xor_auth = (ctypes.c_uint8 * 16)()
    xor_biz = (ctypes.c_uint8 * 16)()
    rc = load().ge_parallel_update(
        table,
        _in(root_key),
        _in(sealed),
        len(sealed),
        threads,
        xor_auth,
        xor_biz,
    )
    if rc != 0:
        raise RuntimeError(f"并行更新失败 rc={rc}")
    return bytes(xor_auth), bytes(xor_biz)
