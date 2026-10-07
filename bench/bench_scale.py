"""千万级密钥管理与百万级并行更新实测。"""

from __future__ import annotations

import json
import multiprocessing
import os
import platform
import secrets
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gmssl import sm2

from grid_epoch.ack import ZALL_LEN
from grid_epoch.aead import open_aead
from grid_epoch.cosign import CollaborativeSM2
from grid_epoch.crypto import free_table, parallel_update, provision_table, stream_ack, stream_topology
from grid_epoch.derive import STREAM_COUNTY_WIDTH, cohort_master, cs_open_key
from grid_epoch.kmc import Cohort
from grid_epoch.subtree import county_zone_count
from grid_epoch.package import ALG_SM2, parse_revocation_package, parse_terminal_package, slice_bytes


RESULT = Path(__file__).resolve().parent / "last_result.json"


def _threads() -> int:
    return max(1, os.cpu_count() or 1)


def _rate(count: int, seconds: float) -> float:
    return count / seconds if seconds > 0 else float("inf")


def _fanout_job(job: tuple) -> int:
    mk_mgmt, mk_biz, area, cohort_id, zone0, zones, per_zone, width = job
    xor_mgmt, xor_biz = stream_topology(
        mk_mgmt, mk_biz, area, cohort_id, zone0, zones, per_zone, width, 1
    )
    if xor_mgmt == bytes(32) or xor_biz == bytes(32):
        raise RuntimeError("扇出派生校验和异常")
    return zones * per_zone


def main() -> None:
    threads = _threads()
    mk_mgmt = secrets.token_bytes(32)
    mk_biz = secrets.token_bytes(32)
    area = 330100

    zones = 100_000
    per_zone = 100
    managed = zones * per_zone
    manage_width = county_zone_count(zones)
    if manage_width != STREAM_COUNTY_WIDTH or county_zone_count(1 << 17) != 256:
        raise SystemExit("生产县宽应为 256")
    print(f"机器 {platform.processor() or platform.machine()}  线程 {threads}")
    print(f"管理规模：{zones} 个台区 × {per_zone} 台 = {managed} 台，密钥流式派生、不落库")
    started = time.perf_counter()
    cohort_id = 7
    xor_mgmt, xor_biz = stream_topology(
        mk_mgmt, mk_biz, area, cohort_id, 0, zones, per_zone, manage_width, threads
    )
    derive_seconds = time.perf_counter() - started
    if xor_mgmt == bytes(32) or xor_biz == bytes(32):
        raise SystemExit("派生校验和异常，结果不可信")
    print(f"  用时 {derive_seconds:.3f} s   {_rate(managed, derive_seconds):,.0f} 台/秒")

    update_zones = 10_000
    update_per = 100
    update_width = county_zone_count(update_zones)
    updating = update_zones * update_per
    cohort_n = 1 << 28
    print(
        f"并行更新：终端树 2^28，每台区 2048 槽，10 万台区，网关树 2^19。"
        f"这一轮实际轮换 {updating} 台"
    )
    master = cohort_master(mk_mgmt, cohort_id)
    cohort = Cohort(cohort_id, cohort_n, master)
    sm2_signer = CollaborativeSM2()

    def sign(data: bytes):
        return [(ALG_SM2, sm2_signer.sign(data))]

    raw_root = cohort.terminals.node_key(1)
    opener = cs_open_key(raw_root)
    if opener == raw_root:
        raise SystemExit("打开密钥不应等于树根")
    started = time.perf_counter()
    release = cohort.publish(
        area,
        0,
        sign,
        escrow_passwords=("甲", "乙"),
        cs_key_for=lambda node_id: cs_open_key(cohort.terminals.node_key(node_id)),
    )
    publish_seconds = time.perf_counter() - started
    if raw_root != cohort.terminals.node_key(1):
        raise SystemExit("节点密钥不应随纪元改变")
    parsed = parse_terminal_package(release.terminal)
    if not sm2_signer.verify(parsed.raw_body, parsed.sm2_signature()):
        raise SystemExit("纪元报文 SM2 验签失败")
    if len(parsed.signatures) != 1:
        raise SystemExit("纪元报文应只有 SM2 签名")
    if 0 in parsed.entries or 1 not in parsed.entries:
        raise SystemExit("无吊销时终端报文应只有根节点")
    plain = open_aead(opener, parsed.entries[1])
    if len(plain) != 36 or int.from_bytes(plain[:4], "big") != 1:
        raise SystemExit("纪元明文不正确")
    rev = parse_revocation_package(release.revocation)
    if len(rev.root) != 32 or len(release.revocation) > 8000:
        raise SystemExit("吊销根报文应当只携带 32 字节根和签名套件")

    started = time.perf_counter()
    table = provision_table(
        mk_mgmt, mk_biz, area, cohort_id, 0, update_zones, update_per, update_width, threads
    )
    provision_seconds = time.perf_counter() - started
    try:
        started = time.perf_counter()
        xor_auth, xor_biz_key = parallel_update(table, opener, parsed.entries[1], threads)
        update_seconds = time.perf_counter() - started
    finally:
        free_table(table)
    if xor_auth == bytes(16) or xor_biz_key == bytes(16):
        raise SystemExit("更新校验和异常，结果不可信")

    nonce = plain[20:36]
    epoch = int.from_bytes(plain[:4], "big")
    started = time.perf_counter()
    ack_update = stream_ack(
        mk_biz, area, cohort_id, 0, update_zones, update_per, update_width, epoch, nonce, threads
    )
    confirm_update_seconds = time.perf_counter() - started
    if ack_update == bytes(16):
        raise SystemExit("百万台确认校验和异常，结果不可信")
    started = time.perf_counter()
    ack_managed = stream_ack(
        mk_biz, area, cohort_id, 0, zones, per_zone, manage_width, epoch, nonce, threads
    )
    confirm_managed_seconds = time.perf_counter() - started
    if ack_managed == bytes(16):
        raise SystemExit("千万台确认校验和异常，结果不可信")

    samples = 30
    started = time.perf_counter()
    for _ in range(samples):
        if not sm2_signer.verify(parsed.raw_body, parsed.sm2_signature()):
            raise SystemExit("纪元报文 SM2 验签失败")
    verify_seconds = (time.perf_counter() - started) / samples
    per_cpu = update_seconds * threads / updating

    crypt = sm2.CryptSM2(public_key=sm2_signer.public_key, private_key="0" * 64)
    started = time.perf_counter()
    for _ in range(samples):
        crypt.encrypt(b"0123456789abcdef")
    sm2_each = (time.perf_counter() - started) / samples
    sm2_million = sm2_each * updating

    print(
        f"  省级组包 {publish_seconds * 1000:.1f} ms，含 3 次 SM2 协同签名："
        f"终端 {len(release.terminal)} 字节，网关 {len(release.gateway)} 字节，"
        f"吊销根 {len(release.revocation)} 字节"
    )
    print(f"  单份终端报文 SM2 验签 {verify_seconds * 1000:.2f} ms（{samples} 次平均，不放进百万循环）")
    print(f"  终端材料准备 {provision_seconds:.3f} s")
    print(
        f"  百万台对称更新模拟 {update_seconds:.3f} s   {_rate(updating, update_seconds):,.0f} 台/秒"
    )
    print(
        f"  分摊到每台约 {per_cpu * 1e6:.1f} µs CPU，只含打开 SM4 密文和派生两把工作密钥"
    )
    print(
        "  一台终端的换代开销是一次验签加这一次对称计算；"
        "上面的墙钟是主机把 100 万次叠在一起的模拟，不是系统时延"
    )
    print(
        f"  百万台确认重算 {confirm_update_seconds:.3f} s   "
        f"{_rate(updating, confirm_update_seconds):,.0f} 台/秒，完成帧 {ZALL_LEN} 字节"
    )
    print(
        f"  千万台确认重算 {confirm_managed_seconds:.3f} s   "
        f"{_rate(managed, confirm_managed_seconds):,.0f} 台/秒"
    )
    print(f"对照：逐台 SM2 加密下发，单次 {sm2_each * 1000:.1f} ms，百万台约 {sm2_million / 3600:.1f} 小时")

    fan_workers = min(4, threads)
    fan_zones = 2500
    fan_per = 100
    fan_width = county_zone_count(fan_zones)
    fan_jobs = [
        (mk_mgmt, mk_biz, area, cohort_id, index * fan_zones, fan_zones, fan_per, fan_width)
        for index in range(fan_workers)
    ]
    started = time.perf_counter()
    with multiprocessing.Pool(fan_workers) as pool:
        fan_counts = pool.map(_fanout_job, fan_jobs)
    fanout_seconds = time.perf_counter() - started
    fanout_terminals = sum(fan_counts)
    print(
        f"本机 {fan_workers} 个进程扇出派生 {fanout_terminals} 台，用时 {fanout_seconds:.3f} s，"
        f"{_rate(fanout_terminals, fanout_seconds):,.0f} 台/秒。这是一台机器上的进程，不是地市广域网"
    )

    report = {
        "machine": platform.platform(),
        "threads": threads,
        "managed_terminals": managed,
        "zones": zones,
        "per_zone": per_zone,
        "derive_seconds": round(derive_seconds, 4),
        "derive_per_second": round(_rate(managed, derive_seconds), 1),
        "derive_checksum_mgmt": xor_mgmt.hex(),
        "update_terminals": updating,
        "cohort_capacity": cohort_n,
        "package_bytes": len(release.terminal),
        "gateway_package_bytes": len(release.gateway),
        "revocation_bytes": len(release.revocation),
        "publish_ms": round(publish_seconds * 1000, 2),
        "verify_ms": round(verify_seconds * 1000, 3),
        "provision_seconds": round(provision_seconds, 4),
        "update_seconds": round(update_seconds, 4),
        "update_per_second": round(_rate(updating, update_seconds), 1),
        "per_terminal_cpu_us": round(per_cpu * 1e6, 2),
        "path_depth": 0,
        "sm2_encrypt_ms": round(sm2_each * 1000, 3),
        "sm2_million_hours": round(sm2_million / 3600, 2),
        "confirm_update_seconds": round(confirm_update_seconds, 4),
        "confirm_update_per_second": round(_rate(updating, confirm_update_seconds), 1),
        "confirm_managed_seconds": round(confirm_managed_seconds, 4),
        "confirm_managed_per_second": round(_rate(managed, confirm_managed_seconds), 1),
        "confirm_bytes_per_zone": ZALL_LEN,
        "slice_bytes_at_1000": slice_bytes(1000),
        "terminal_tree": cohort_n,
        "zone_span": cohort.span,
        "gateway_tree": cohort.gateways.n,
        "fanout_workers": fan_workers,
        "fanout_terminals": fanout_terminals,
        "fanout_seconds": round(fanout_seconds, 4),
        "fanout_per_second": round(_rate(fanout_terminals, fanout_seconds), 1),
    }
    RESULT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果已写入 {RESULT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
