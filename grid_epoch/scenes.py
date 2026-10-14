"""一条时间线上的元命令。单步会先静默执行前面的步骤，再打印这一步。"""

from __future__ import annotations

import secrets
import sys

from .ack import encode_zall, xor_tags
from .errors import AuthFailed, EpochRejected, ProtocolError, TerminalRevoked
from .kmc import ProvincialKMC
from .package import parse_gateway_package, parse_revocation_package, parse_terminal_package


_PASS_A = "值班甲"
_PASS_B = "值班乙"
_COVER = {"cs": "完全子树", "sd": "子集差"}
_ENERGY = "Ua=10.21;Ub=10.18;Uc=10.20;Ia=15.4;status=ok".encode()
_CONTROL = "合闸".encode()


class Story:
    def __init__(self) -> None:
        self.kmc: ProvincialKMC | None = None
        self.gateway = None
        self.terminals: dict[int, object] = {}
        self.path0: dict[int, bytes] | None = None
        self.epoch1: bytes | None = None
        self.withheld_rejected = False
        self.zone_mgmt_before: bytes | None = None

    def close(self) -> None:
        kmc = self.kmc
        if kmc is not None:
            kmc.hsm.cosign.close()

    @property
    def cohort(self):
        return self.kmc.cohorts[1]


def _carry(name: str, *facts: str) -> str:
    return "承接  " + name + "  " + "  ".join(facts)


def _sync(story: Story, zone_id: int, release) -> None:
    gateway = story.kmc.gateways[zone_id]
    gateway.sync(release.gateway)
    gateway.sync_revocation(release.revocation, story.kmc.proofs_for_zone(zone_id))
    if zone_id == 42:
        story.gateway = gateway


def _sm2_ok(story: Story, blob: bytes, parse) -> bool:
    package = parse(blob)
    return story.kmc.hsm.cosign.verify(package.raw_body, package.sm2_signature())


def _publish_facts(story: Story, release) -> dict:
    terminal_ok = _sm2_ok(story, release.terminal, parse_terminal_package)
    gateway_ok = _sm2_ok(story, release.gateway, parse_gateway_package)
    revocation_ok = _sm2_ok(story, release.revocation, parse_revocation_package)
    cover = parse_terminal_package(release.terminal).cover
    kind, subsets = story.kmc.recall_plan(1)
    assert kind == cover
    return {
        "epoch": release.epoch,
        "terminal_bytes": len(release.terminal),
        "gateway_bytes": len(release.gateway),
        "revocation_bytes": len(release.revocation),
        "sm2": terminal_ok and gateway_ok and revocation_ok,
        "cover": cover,
        "subsets": subsets,
    }


def _blocked(terminal, blob: bytes, error: type[Exception]) -> bool:
    try:
        terminal.apply(blob)
    except error:
        return True
    return False


def _revoked_terminals(story: Story) -> int:
    return sum(1 for record in story.kmc.registry.values() if record.revoked)


def init(story: Story) -> dict:
    story.kmc = ProvincialKMC(area=330100)
    story.kmc.arm_escrow(_PASS_A, _PASS_B)
    # 16 叶只有两个台区槽。台区 43 和台区 45 要同时存在，换表还要一片新叶子，所以用 32 叶。
    story.kmc.create_cohort(1, 32)
    story.gateway = story.kmc.register_zone(42, 1)
    story.kmc.register_zone(43, 1)
    for local in range(4):
        story.terminals[local] = story.kmc.enroll(42, local)
    tree = story.cohort.terminals
    for batch in range(tree.span // tree.batch):
        story.kmc.set_firmware(42, batch, 1)
    story.path0 = {node: bytes(key) for node, key in story.terminals[0].path_keys.items()}
    assert story.cohort.epoch == 0
    assert len(story.terminals) == 4
    assert _revoked_terminals(story) == 0
    assert not story.cohort.terminals.revoked
    versions = [
        story.kmc.cities[1].firmware_version(42, batch) for batch in range(tree.span // tree.batch)
    ]
    assert versions == [1] * (tree.span // tree.batch)
    return {
        "epoch": 0,
        "enrolled": 4,
        "revoked_empty": True,
        "firmware": 1,
        "recalled": False,
        "lines": [
            _carry("init", "尚无纪元"),
            "区域 330100。台区 42 序号 0–3、台区 43 已登记",
            "纪元 0。四台在册。吊销集为空",
            "固件版本已标为 1，这一步不召回",
        ],
    }


def epoch0(story: Story) -> dict:
    terminal = story.terminals[0]
    assert story.cohort.epoch == 0
    assert not story.kmc.registry[terminal.tid].revoked
    rejected = False
    try:
        terminal.seal_telemetry(b"epoch-zero")
    except EpochRejected:
        rejected = True
    assert rejected
    assert story.cohort.epoch == 0
    assert len(story.terminals) == 4
    return {
        "rejected": True,
        "lines": [
            _carry("epoch0", "纪元 0", "序号 0 在册"),
            "序号 0 做业务被拒绝",
            "纪元仍为 0",
            "四台仍在册",
        ],
    }


def publish(story: Story) -> dict:
    assert story.cohort.epoch == 0
    release = story.kmc.publish(1, 42)
    story.epoch1 = release.terminal
    _sync(story, 42, release)
    for local in (0, 1, 2):
        story.terminals[local].apply(release.terminal)
    facts = _publish_facts(story, release)
    assert facts["epoch"] == 1
    assert facts["sm2"]
    assert facts["cover"] == "cs"
    assert [story.terminals[local].epoch for local in (0, 1, 2)] == [1, 1, 1]
    assert story.terminals[3].epoch == 0
    assert story.kmc.gateways[43].epoch < story.cohort.epoch
    return {
        **facts,
        "left_behind": story.terminals[3].epoch,
        "lines": [
            _carry("publish", "纪元 0"),
            (
                f"进入纪元 {facts['epoch']}。终端报文 {facts['terminal_bytes']} 字节，"
                f"网关报文 {facts['gateway_bytes']} 字节，吊销根 {facts['revocation_bytes']} 字节"
            ),
            "SM2 通过，覆盖为完全子树",
            "序号 0、1、2 进入纪元 1。序号 3 仍在纪元 0。台区 43 未收到",
        ],
    }


def auth(story: Story) -> dict:
    terminal = story.terminals[0]
    assert story.cohort.epoch == 1
    assert terminal.epoch == 1
    challenge = secrets.token_bytes(16)
    assert story.gateway.verify_proof(terminal.tid, challenge, terminal.prove(challenge))
    return {
        "passed": True,
        "lines": [
            _carry("auth", "纪元 1", "序号 0 已进入"),
            "序号 0 认证通过",
            "台区 42 核对通过",
            "纪元仍为 1",
        ],
    }


def energy(story: Story) -> dict:
    terminal = story.terminals[0]
    assert story.cohort.epoch == 1
    assert terminal.epoch == 1
    opened = story.kmc.open_uplink(story.gateway.accept_and_wrap(terminal.seal_telemetry(_ENERGY)))
    assert opened == _ENERGY
    rejected = False
    try:
        story.gateway.derive_business_key(terminal.tid)
    except PermissionError:
        rejected = True
    assert rejected
    return {
        "opened": True,
        "business_rejected": True,
        "lines": [
            _carry("energy", "纪元 1", "序号 0 已认证"),
            f"主站解开电能量明文：{opened.decode()}",
            "台区派生业务密钥被拒绝",
            "纪元仍为 1",
        ],
    }


def control(story: Story) -> dict:
    terminal = story.terminals[0]
    assert story.cohort.epoch == 1
    gateway_record = terminal.seal_control(_CONTROL)
    station_record = terminal.seal_control(_CONTROL)
    assert story.gateway.open_control(gateway_record) == _CONTROL
    assert story.kmc.open_uplink(story.gateway.accept_and_wrap(station_record)) == _CONTROL
    return {
        "gateway_opened": True,
        "station_opened": True,
        "lines": [
            _carry("control", "纪元 1"),
            "台区打开控制报文",
            "主站也能打开",
            "纪元仍为 1",
        ],
    }


def passwords(story: Story) -> dict:
    assert story.cohort.epoch == 1
    wrong = False
    try:
        story.kmc.recover_nonces(1, 1, _PASS_A, "错")
    except AuthFailed:
        wrong = True
    assert wrong
    opened = story.kmc.recover_nonces(1, 1, _PASS_A, _PASS_B)
    assert len(opened) == 2
    del opened
    return {
        "one_failed": True,
        "both_ok": True,
        "epoch": story.cohort.epoch,
        "lines": [
            _carry("passwords", "纪元仍为 1"),
            "一份口令失败",
            "两份口令通过",
            "随机数未显示",
        ],
    }


def escrow(story: Story) -> dict:
    assert 1 in story.cohort.escrow
    opened = story.kmc.recover_nonces(1, 1, _PASS_A, _PASS_B)
    assert len(opened[0]) == 16 and len(opened[1]) == 16
    del opened
    return {
        "opened": True,
        "shown": False,
        "lines": [
            _carry("escrow", "纪元 1 的托管还在"),
            "纪元 1 的托管已打开",
            "随机数未显示",
            "纪元仍为 1",
        ],
    }


def enroll(story: Story) -> dict:
    terminal = story.terminals[0]
    assert story.cohort.epoch == 1
    assert not story.kmc.registry[terminal.tid].revoked
    challenge = secrets.token_bytes(16)
    signature = terminal.sign_enrollment(challenge)
    assert story.kmc.verify_enrollment(terminal.tid, challenge, signature, terminal.epoch)
    assert story.cohort.epoch == 1
    assert not story.kmc.registry[terminal.tid].revoked
    return {
        "passed": True,
        "epoch": 1,
        "lines": [
            _carry("enroll", "纪元 1", "序号 0 在册"),
            "序号 0 的 SM9 接入通过",
            "纪元仍为 1",
            "序号 0 仍在册",
        ],
    }


def watch(story: Story) -> dict:
    assert story.gateway.epoch == story.cohort.epoch == 1
    assert story.kmc.gateways[43].epoch < story.cohort.epoch
    behind = sorted(zone for zone, gateway in story.kmc.gateways.items() if gateway.epoch < story.cohort.epoch)
    assert behind == [43]
    return {
        "zones": behind,
        "lines": [
            _carry("watch", "台区 42 已收到纪元 1", "台区 43 未收到"),
            "观察名单是台区 43",
            "未收到报文",
            "不参与验签，也不是确认失败",
        ],
    }


def jump(story: Story) -> dict:
    assert story.terminals[3].epoch == 0
    assert [story.terminals[local].epoch for local in (0, 1, 2)] == [1, 1, 1]
    release = story.kmc.publish(1, 42)
    _sync(story, 42, release)
    story.terminals[3].apply(release.terminal)
    assert story.terminals[3].epoch == 2
    old_rejected = _blocked(story.terminals[3], story.epoch1, EpochRejected)
    assert old_rejected
    for local in (0, 1, 2):
        story.terminals[local].apply(release.terminal)
    assert [story.terminals[local].epoch for local in range(4)] == [2, 2, 2, 2]
    return {
        "entered": story.terminals[3].epoch,
        "old_rejected": True,
        "lines": [
            _carry("jump", "序号 3 仍在纪元 0", "其余已在纪元 1"),
            "发布后序号 3 直接进入纪元 2",
            "把纪元 1 的旧报文交给它，被拒绝",
            "序号 0、1、2 也进入纪元 2",
        ],
    }


def drop(story: Story) -> dict:
    assert story.cohort.epoch == 2
    assert 1 in story.cohort.escrow
    story.kmc.drop_expired(1, 2)
    assert story.cohort.epoch == 2
    blocked = False
    try:
        story.kmc.business_key_at(story.terminals[0].tid, 1)
    except EpochRejected:
        blocked = True
    assert blocked
    return {
        "epoch": story.cohort.epoch,
        "epoch1_blocked": True,
        "lines": [
            _carry("drop", "当前纪元 2", "纪元 1 曾经有托管"),
            "纪元 2 之前的随机数已丢弃",
            "当前纪元仍为 2",
            "纪元 1 不能从在线状态重算",
        ],
    }


def withhold(story: Story) -> dict:
    assert story.cohort.epoch == 2
    assert all(story.terminals[local].epoch == 2 for local in range(4))
    assert _revoked_terminals(story) == 0
    assert not story.cohort.terminals.revoked
    present = [story.terminals[local] for local in (0, 2, 3)]
    for terminal in present:
        story.gateway.submit_ack(terminal.tid, terminal.ack(), terminal.completion_tag())
    forged = encode_zall(
        42,
        story.gateway.epoch,
        4,
        xor_tags([terminal.completion_tag() for terminal in present]),
        story.gateway.link_key,
    )
    rejected = False
    try:
        story.kmc.accept_report(42, forged)
    except AuthFailed:
        rejected = True
    assert rejected
    named = story.kmc.localize_report(42, story.gateway.detail_report())
    missing = {story.terminals[local].tid for local in range(4)} - named
    assert missing == {story.terminals[1].tid}
    assert _revoked_terminals(story) == 0
    story.withheld_rejected = True
    return {
        "rejected": True,
        "missing_local": 1,
        "revoked": 0,
        "lines": [
            _carry("withhold", "纪元 2", "四台都能收当前报文", "吊销集为空"),
            "扣下序号 1，完成帧被拒绝",
            "缺的是序号 1",
            "吊销数仍为 0",
        ],
    }


def confirm(story: Story) -> dict:
    assert story.withheld_rejected
    assert _revoked_terminals(story) == 0
    story.gateway.reset_acks()
    live = [story.terminals[local] for local in range(4)]
    for terminal in live:
        story.gateway.submit_ack(terminal.tid, terminal.ack(), terminal.completion_tag())
    token = story.gateway.completion_report()
    assert token.startswith(b"ZALL") and len(token) == 62
    confirmed = story.kmc.accept_report(42, token)
    assert confirmed == {terminal.tid for terminal in live}
    return {
        "bytes": len(token),
        "count": 4,
        "lines": [
            _carry("confirm", "上一帧被拒绝", "吊销数仍为 0"),
            "四台交齐",
            "完成帧 62 字节",
            "主站接受这一帧",
        ],
    }


def revoke(story: Story) -> dict:
    victim = story.terminals[2]
    assert not story.kmc.registry[victim.tid].revoked
    assert story.cohort.epoch >= 2
    story.kmc.revoke(victim.tid)
    release = story.kmc.publish(1, 42)
    _sync(story, 42, release)
    for local in (0, 1, 3):
        story.terminals[local].apply(release.terminal)
    assert _blocked(victim, release.terminal, TerminalRevoked)
    facts = _publish_facts(story, release)
    assert facts["cover"] == "sd"
    assert [story.terminals[local].epoch for local in (0, 1, 3)] == [facts["epoch"]] * 3
    assert victim.epoch < facts["epoch"]
    return {
        "opened": False,
        "cover": facts["cover"],
        "subsets": facts["subsets"],
        "epoch": facts["epoch"],
        "lines": [
            _carry("revoke", "序号 2 在册", "当前纪元已确认过"),
            f"吊销序号 2 并发布新纪元 {facts['epoch']}",
            "序号 2 解不开",
            "序号 0、1、3 和新纪元对齐",
            f"覆盖为子集差，子集 {facts['subsets']} 条",
        ],
    }


def replace(story: Story) -> dict:
    assert story.kmc.registry[story.terminals[2].tid].revoked
    fresh = story.kmc.enroll(42, 4)
    release = story.kmc.publish(1, 42)
    _sync(story, 42, release)
    fresh.apply(release.terminal)
    for local in (0, 1, 3):
        story.terminals[local].apply(release.terminal)
    assert fresh.epoch == story.cohort.epoch
    assert story.terminals[0].epoch == fresh.epoch
    assert _blocked(story.terminals[2], release.terminal, TerminalRevoked)
    assert {node: bytes(key) for node, key in story.terminals[0].path_keys.items()} == story.path0
    story.terminals[4] = fresh
    epoch = story.cohort.epoch
    return {
        "local": 4,
        "leaf": fresh.leaf,
        "epoch": epoch,
        "path_same": True,
        "old_blocked": True,
        "lines": [
            _carry("replace", "序号 2 已吊销", f"纪元 {epoch}"),
            f"新序号 4 进入纪元 {epoch}，新叶子 {fresh.leaf}",
            "序号 2 仍解不开",
            "序号 0 沿用灌装时的路径密钥进入同一纪元",
        ],
    }


def transfer(story: Story) -> dict:
    assert not story.kmc.registry[story.terminals[1].tid].revoked
    assert 45 not in story.kmc.gateways
    story.kmc.register_zone(45, 1)
    moved = story.kmc.transfer(story.terminals[1], 45, 5)
    release = story.kmc.publish(1, 45)
    _sync(story, 45, release)
    moved.apply(release.terminal)
    assert moved.epoch == story.cohort.epoch
    assert _blocked(story.terminals[1], release.terminal, TerminalRevoked)
    assert story.kmc.registry[story.terminals[1].tid].revoked
    return {
        "zone": 45,
        "local": 5,
        "epoch": moved.epoch,
        "old_blocked": True,
        "lines": [
            _carry("transfer", "序号 1 在册", "台区 45 尚未出现"),
            "序号 1 割到台区 45 序号 5",
            "旧叶子拒绝",
            f"新序号进入当前纪元 {moved.epoch}",
        ],
    }


def gateway(story: Story) -> dict:
    live = [
        record
        for record in story.kmc.registry.values()
        if record.zone == 42 and not record.revoked and not record.destroyed
    ]
    assert live
    before = bytes(story.kmc._zone_mgmt(42))
    story.kmc.revoke_gateway(42)
    story.gateway = story.kmc.gateways[42]
    after = bytes(story.kmc._zone_mgmt(42))
    assert before == after == bytes(story.gateway.zone_mgmt)
    assert any(record.zone == 42 and not record.revoked and not record.destroyed for record in story.kmc.registry.values())
    story.zone_mgmt_before = before
    return {
        "rotated": False,
        "lines": [
            _carry("gateway", "台区 42 仍有在册终端"),
            "台区 42 的网关槽作废",
            "台区管控密钥未轮换",
            "在册终端仍在",
        ],
    }


def reprovision(story: Story) -> dict:
    record = story.kmc.registry[story.terminals[0].tid]
    assert not record.revoked and not record.destroyed
    before = bytes(story.terminals[0].seed_mgmt)
    story.kmc.reprovision(story.terminals[0])
    assert bytes(story.terminals[0].seed_mgmt) == before
    assert not story.kmc.registry[story.terminals[0].tid].revoked
    return {
        "same": True,
        "lines": [
            _carry("reprovision", "序号 0 在册且未销毁"),
            "序号 0 重新灌装",
            "管理种子与原先一致",
            "序号 0 仍在册",
        ],
    }


def destroy(story: Story) -> dict:
    terminal = story.terminals[3]
    record = story.kmc.registry[terminal.tid]
    assert not record.revoked and not record.destroyed
    leaf = terminal.leaf
    revoked = set(story.cohort.terminals.revoked)
    story.kmc.destroy_record(terminal.tid)
    assert story.kmc.registry[terminal.tid].destroyed
    assert leaf not in story.cohort.terminals.revoked
    assert set(story.cohort.terminals.revoked) == revoked
    return {
        "leaf": leaf,
        "kept": True,
        "in_revoked": False,
        "lines": [
            _carry("destroy", "序号 3 在册", f"叶子 {leaf}"),
            "序号 3 档案已销毁",
            f"叶子 {leaf} 保留",
            "吊销集不因此加入这片叶子",
        ],
    }


def _destroyed_error(action) -> str:
    try:
        action()
    except ProtocolError as exc:
        return str(exc)
    return ""


def reject_enroll(story: Story) -> dict:
    terminal = story.terminals[3]
    record = story.kmc.registry[terminal.tid]
    assert record.destroyed
    assert terminal.leaf not in story.cohort.terminals.revoked
    challenge = secrets.token_bytes(16)
    signature = terminal.sign_enrollment(challenge)
    revoked = set(story.cohort.terminals.revoked)
    assert story.kmc.verify_enrollment(terminal.tid, challenge, signature, terminal.epoch) is False
    assert terminal.leaf not in story.cohort.terminals.revoked
    assert set(story.cohort.terminals.revoked) == revoked
    return {
        "rejected": True,
        "lines": [
            _carry("reject-enroll", "序号 3 已销毁", "叶子保留"),
            "接入核验失败",
            "叶子仍保留",
            "吊销集不因此改变",
        ],
    }


def reject_transfer(story: Story) -> dict:
    assert story.kmc.registry[story.terminals[3].tid].destroyed
    message = _destroyed_error(lambda: story.kmc.transfer(story.terminals[3], 45, 6))
    assert message == "终端已销毁"
    assert story.terminals[3].leaf not in story.cohort.terminals.revoked
    return {
        "rejected": True,
        "lines": [
            _carry("reject-transfer", "序号 3 已销毁"),
            "割接被拒绝",
            "终端已销毁",
            "叶子仍保留",
        ],
    }


def reject_reprovision(story: Story) -> dict:
    assert story.kmc.registry[story.terminals[3].tid].destroyed
    message = _destroyed_error(lambda: story.kmc.reprovision(story.terminals[3]))
    assert message == "终端已销毁"
    assert story.terminals[3].leaf not in story.cohort.terminals.revoked
    return {
        "rejected": True,
        "lines": [
            _carry("reject-reprovision", "序号 3 已销毁"),
            "重新灌装被拒绝",
            "终端已销毁",
            "叶子仍保留",
        ],
    }


def recall(story: Story) -> dict:
    tree = story.cohort.terminals
    width = tree.span // tree.batch
    assert [story.kmc.cities[1].firmware_version(42, batch) for batch in range(width)] == [1] * width
    leaf = story.terminals[3].leaf
    assert leaf not in tree.revoked
    batches = story.kmc.recall_firmware(42, 1)
    kind, subsets = story.kmc.recall_plan(1)
    assert kind == "sd"
    assert batches >= 1
    return {
        "batches": batches,
        "cover": kind,
        "subsets": subsets,
        "lines": [
            _carry("recall", "台区 42 固件版本为 1", "此前销毁未把叶子放进吊销集"),
            "召回固件 1",
            f"摘掉 {batches} 个批次",
            f"子集差 {subsets} 条",
        ],
    }


STEPS = (
    ("init", init),
    ("epoch0", epoch0),
    ("publish", publish),
    ("auth", auth),
    ("energy", energy),
    ("control", control),
    ("passwords", passwords),
    ("escrow", escrow),
    ("enroll", enroll),
    ("watch", watch),
    ("jump", jump),
    ("drop", drop),
    ("withhold", withhold),
    ("confirm", confirm),
    ("revoke", revoke),
    ("replace", replace),
    ("transfer", transfer),
    ("gateway", gateway),
    ("reprovision", reprovision),
    ("destroy", destroy),
    ("reject-enroll", reject_enroll),
    ("reject-transfer", reject_transfer),
    ("reject-reprovision", reject_reprovision),
    ("recall", recall),
)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    names = [name for name, _fn in STEPS]
    if len(args) != 1 or args[0] not in {"run", *names}:
        print("可用名字: " + " ".join(names))
        return 1
    chosen = args[0]
    story = Story()
    try:
        for name, fn in STEPS:
            result = fn(story)
            if chosen == "run" or name == chosen:
                for line in result["lines"]:
                    print(line)
                print()
            if name == chosen:
                break
    finally:
        story.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
