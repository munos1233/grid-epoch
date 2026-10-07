"""可向评审现场演示的完整业务流程。"""

from __future__ import annotations

import atexit
import secrets

from .ack import encode_zall, xor_tags
from .errors import AuthFailed, EpochRejected, TerminalRevoked
from .kmc import ProvincialKMC
from .session import ProvisionSession


def main() -> None:
    area = 330100
    zone_id = 42
    kmc = ProvincialKMC(area=area)
    kmc.arm_escrow("甲", "乙")
    kmc.create_cohort(cohort_id=1, n_leaves=16)
    session = ProvisionSession(kmc, 1)
    gateway = kmc.register_zone(zone_id, cohort_id=1)
    session.register(zone_id)
    atexit.register(session.close)
    terminals = [session.enroll(zone_id, local) for local in range(4)]
    offline = terminals[3]

    print("衍枢 GridEpoch  ·  海量配电终端批量密钥管理")
    print(f"区域 {area}  台区 {zone_id}  更新簇容量 16  已接入终端 {len(terminals)}")
    print(f"省级签名公钥（SM2，前 32 位十六进制） {kmc.hsm.public_key[:32]}…")
    print()

    rejected_early = False
    try:
        terminals[0].seal_telemetry(b"before-activation")
    except EpochRejected as exc:
        rejected_early = True
        print(f"1. 灌装纪元不能做业务：{exc}")
    assert rejected_early

    activation = kmc.publish(1)
    gateway.sync(activation.gateway)
    gateway.sync_revocation(activation.revocation, kmc.proofs_for_zone(zone_id))
    for terminal in terminals[:3]:
        terminal.apply(activation.terminal)
    print(
        f"   激活报文：终端 {len(activation.terminal)} 字节，"
        f"网关 {len(activation.gateway)} 字节，吊销根 {len(activation.revocation)} 字节"
    )

    challenge = secrets.token_bytes(16)
    proof = terminals[0].prove(challenge)
    assert gateway.verify_proof(terminals[0].tid, challenge, proof)
    print("2. 分级认证")
    print("   台区42-0号终端用认证密钥响应挑战，台区用管控种子重算校验：通过")

    payload = "Ua=10.21;Ub=10.18;Uc=10.20;Ia=15.4;status=ok".encode()
    opened = kmc.open_uplink(gateway.accept_and_wrap(terminals[0].seal_telemetry(payload)))
    assert opened == payload
    print("3. 分级加密")
    print("   业务明文由终端业务密钥做 SM4 加密，台区只校验认证标签并加链路 MAC")
    print(f"   主站解开上行报文：{opened.decode()}")
    try:
        gateway.derive_business_key(terminals[0].tid)
    except PermissionError as exc:
        print(f"   台区尝试派生业务密钥：被拒绝（{exc}）")
    print()

    jumped = kmc.publish(1)
    offline.apply(jumped.terminal)
    assert offline.epoch == 2
    assert offline.device_keys() == kmc.device_keys(offline.tid)
    rejected_old = False
    try:
        offline.apply(activation.terminal)
    except EpochRejected as exc:
        rejected_old = True
        print(f"4. 离线直达：漏掉纪元 1 的终端直接进入纪元 {offline.epoch}，旧报文被拒绝（{exc}）")
    assert rejected_old
    gateway.sync(jumped.gateway)
    gateway.sync_revocation(jumped.revocation, kmc.proofs_for_zone(zone_id))
    for terminal in terminals[:3]:
        terminal.apply(jumped.terminal)
    print()

    victim = terminals[2]
    kmc.revoke(victim.tid)
    revoked = kmc.publish(1)
    gateway.sync(revoked.gateway)
    gateway.sync_revocation(revoked.revocation, kmc.proofs_for_zone(zone_id))
    for terminal in (terminals[0], terminals[1], offline):
        terminal.apply(revoked.terminal)
        assert terminal.device_keys() == kmc.device_keys(terminal.tid)
    rejected_victim = False
    try:
        victim.apply(revoked.terminal)
    except TerminalRevoked as exc:
        rejected_victim = True
        print(f"5. 吊销：台区42-{victim.leaf}号停在纪元 {victim.epoch}，解不开纪元 {kmc.cohorts[1].epoch}（{exc}）")
    assert rejected_victim
    assert victim.epoch == 2
    fresh = terminals[0].seal_telemetry(b"epoch3-telemetry")
    assert kmc.open_uplink(gateway.accept_and_wrap(fresh)) == b"epoch3-telemetry"
    present = (terminals[0], offline)
    withheld = terminals[1]
    revoked_leaves = set(kmc.cohorts[1].terminals.revoked)
    epoch_now = kmc.cohorts[1].epoch
    for terminal in present:
        gateway.submit_ack(terminal.tid, terminal.ack(), terminal.completion_tag())
    forged = encode_zall(
        zone_id,
        gateway.epoch,
        3,
        xor_tags([terminal.completion_tag() for terminal in present]),
        gateway.link_key,
    )
    rejected_full = False
    try:
        kmc.accept_report(zone_id, forged)
    except AuthFailed as exc:
        rejected_full = True
        print(f"6. 确认：扣下 1 台仍报完成帧，主站拒绝（{exc}）")
    assert rejected_full
    named = kmc.localize_report(zone_id, gateway.detail_report())
    assert {terminals[0].tid, offline.tid, withheld.tid} - named == {withheld.tid}
    assert set(kmc.cohorts[1].terminals.revoked) == revoked_leaves
    assert kmc.cohorts[1].epoch == epoch_now
    print(f"   明细只缺台区内序号 {withheld.tid & 0xFFFF}，吊销集不变")
    gateway.reset_acks()
    for terminal in (terminals[0], terminals[1], offline):
        gateway.submit_ack(terminal.tid, terminal.ack(), terminal.completion_tag())
    token = gateway.completion_report()
    assert token.startswith(b"ZALL") and len(token) == 62
    assert kmc.accept_report(zone_id, token) == {terminals[0].tid, terminals[1].tid, offline.tid}
    print(f"   3 台交齐后完成帧 {len(token)} 字节，主站用业务密钥核对通过")
    print()

    skipper = terminals[1]
    renewed = session.enroll(zone_id, 99)
    assert renewed.leaf != victim.leaf
    reused = kmc.publish(1)
    gateway.sync(reused.gateway)
    gateway.sync_revocation(reused.revocation, kmc.proofs_for_zone(zone_id))
    renewed.apply(reused.terminal)
    skipper.apply(reused.terminal)
    offline.apply(reused.terminal)
    assert renewed.device_keys() == kmc.device_keys(renewed.tid)
    assert skipper.device_keys() == kmc.device_keys(skipper.tid)
    rejected_old = False
    try:
        victim.apply(reused.terminal)
    except TerminalRevoked as exc:
        rejected_old = True
        print(f"7. 换表：新终端用叶子 {renewed.leaf}，旧表解不开（{exc}）")
        print("   邻表仍用灌装时的路径密钥进入最新纪元")
    assert rejected_old
    print()
    print("运行 python bench/bench_scale.py 可实测千万级派生与百万级并行更新。")


if __name__ == "__main__":
    main()
