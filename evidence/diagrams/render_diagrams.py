"""Render the six answer-defense diagrams as editable SVG and matching PNG.

Run: python3 evidence/diagrams/render_diagrams.py
All labels remain SVG text (rather than being converted to vector outlines).
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Polygon


OUT = Path(__file__).resolve().parent
FONT = font_manager.FontProperties(fname="/System/Library/Fonts/Hiragino Sans GB.ttc")
plt.rcParams["svg.fonttype"] = "none"
plt.rcParams["savefig.facecolor"] = "#F5F8FC"

NAVY = "#12304B"
MUTED = "#53697D"
LINE = "#A8B8C7"
BG = "#F5F8FC"
WHITE = "#FFFFFF"
BLUE = "#2463A3"
BLUE_SOFT = "#EAF3FC"
TEAL = "#087C83"
TEAL_SOFT = "#E7F6F4"
ORANGE = "#B46716"
ORANGE_SOFT = "#FFF3E3"
PURPLE = "#6D52A5"
PURPLE_SOFT = "#F1EDFA"
RED = "#B54A4D"
RED_SOFT = "#FBEDED"
GREY_SOFT = "#EAF0F5"


def canvas(number: int, title: str, subtitle: str, height: int = 1000):
    fig = plt.figure(figsize=(16, height / 100), dpi=150, facecolor=BG)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1600)
    ax.set_ylim(height, 0)
    ax.axis("off")
    ax.set_facecolor(BG)
    ax.text(58, 67, f"图 {number}  {title}", color=NAVY, fontsize=29,
            fontweight="bold", fontproperties=FONT, va="center")
    ax.text(60, 106, subtitle, color=MUTED, fontsize=16,
            fontproperties=FONT, va="center")
    ax.plot([60, 1540], [132, 132], color="#D8E2EA", lw=1.5)
    return fig, ax


def txt(ax, x, y, text, size=17, color=NAVY, align="left", weight="normal", va="center"):
    ax.text(x, y, text, color=color, fontsize=size, ha=align, va=va,
            fontweight=weight, fontproperties=FONT, linespacing=1.46)


def box(ax, x, y, w, h, title, body=(), *, color=BLUE, fill=WHITE,
        title_size=20, body_size=16, edge=None, pad=22, radius=18,
        body_start=None, line_height=31):
    edge = edge or color
    patch = FancyBboxPatch((x, y), w, h,
                           boxstyle=f"round,pad=0.012,rounding_size={radius}",
                           linewidth=1.7, edgecolor=edge, facecolor=fill)
    ax.add_patch(patch)
    txt(ax, x + pad, y + 35, title, title_size, color=color, weight="bold")
    by = body_start if body_start is not None else y + 79
    for i, line in enumerate(body):
        txt(ax, x + pad, by + i * line_height, line, body_size, color=NAVY)
    return patch


def centered(ax, x, y, w, h, label, *, color=BLUE, fill=WHITE, size=20,
             edge=None, weight="bold", radius=16):
    patch = FancyBboxPatch((x, y), w, h,
                           boxstyle=f"round,pad=0.01,rounding_size={radius}",
                           linewidth=1.7, edgecolor=edge or color, facecolor=fill)
    ax.add_patch(patch)
    txt(ax, x + w / 2, y + h / 2, label, size, color=color, align="center", weight=weight)
    return patch


def path(ax, pts, *, color=LINE, lw=2.1, style="solid", arrow=True,
         mutation=19):
    for a, b in zip(pts[:-2], pts[1:-1]):
        ax.plot([a[0], b[0]], [a[1], b[1]], color=color, lw=lw, ls=style,
                solid_capstyle="round")
    a, b = pts[-2], pts[-1]
    if arrow:
        ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>",
                                     mutation_scale=mutation, lw=lw,
                                     linestyle=style, color=color,
                                     shrinkA=0, shrinkB=0))
    else:
        ax.plot([a[0], b[0]], [a[1], b[1]], color=color, lw=lw, ls=style)


def note(ax, x, y, w, h, text, *, color=BLUE, fill=BLUE_SOFT,
         size=16, edge=None, align="left"):
    p = FancyBboxPatch((x, y), w, h,
                       boxstyle="round,pad=0.01,rounding_size=14",
                       linewidth=1.2, edgecolor=edge or color, facecolor=fill)
    ax.add_patch(p)
    tx = x + 18 if align == "left" else x + w / 2
    txt(ax, tx, y + h / 2, text, size, color=color, align=align)


def save(fig, stem):
    fig.savefig(OUT / f"{stem}.svg", format="svg", dpi=150)
    fig.savefig(OUT / f"{stem}.png", format="png", dpi=150)
    plt.close(fig)


def fig1():
    fig, ax = canvas(1, "进程与密钥边界", "八个运行实体；每个框只列自己持有、接收或明确缺失的材料。")
    box(ax, 50, 185, 300, 260, "值班台", [
        "双人口令核对与操作入口", "页面不读取第三份分片", "只显示核对、发布与审计结果",
    ], color=BLUE, fill=BLUE_SOFT)
    box(ax, 390, 185, 430, 260, "省级软件模块", [
        "mk_mgmt、mk_biz、SM9 主私钥", "广播树根；协同签名调用方 d1", "没有设备 SM2 私钥", "不拼出完整协同签名私钥",
    ], color=PURPLE, fill=PURPLE_SOFT)
    box(ax, 860, 185, 300, 260, "协同签名进程", [
        "只持有另一份 d2", "与调用方完成 SM2 签名", "不拼出完整私钥",
    ], color=PURPLE, fill=PURPLE_SOFT)
    box(ax, 1200, 185, 340, 260, "保管进程", [
        "只接收第三份分片", "不接收两份口令", "与值班台分进程保存",
    ], color=BLUE, fill=BLUE_SOFT)

    box(ax, 50, 620, 360, 275, "地市进程", [
        "持委托密钥与本节点广播密钥", "没有省级主密钥和广播树根", "只封装种子，打不开灌装包",
    ], color=TEAL, fill=TEAL_SOFT)
    box(ax, 450, 620, 350, 275, "产线进程", [
        "本地生成设备 SM2 密钥对", "持设备私钥；打开种子封装", "打开省级 SM9 私钥封装",
    ], color=TEAL, fill=TEAL_SOFT)
    box(ax, 840, 620, 320, 275, "台区", [
        "持台区管控密钥", "做接入认证、控制与确认汇聚", "没有业务种子",
    ], color=ORANGE, fill=ORANGE_SOFT)
    box(ax, 1200, 620, 340, 275, "终端", [
        "持设备私钥和两颗种子", "本地派生认证、业务密钥", "接收单条广播覆盖密文",
    ], color=ORANGE, fill=ORANGE_SOFT)

    path(ax, [(350, 302), (390, 302)], color=BLUE)
    path(ax, [(820, 302), (860, 302)], color=PURPLE)
    path(ax, [(710, 185), (710, 157), (1370, 157), (1370, 185)], color=BLUE, style="dashed")
    txt(ax, 1060, 148, "托管第三份分片", 14, BLUE, "center")
    path(ax, [(510, 445), (510, 550), (230, 550), (230, 620)], color=TEAL)
    txt(ax, 292, 528, "委托与本节点材料", 14, TEAL, "center")
    path(ax, [(680, 445), (680, 620)], color=TEAL)
    txt(ax, 696, 535, "SM9 封装", 14, TEAL)
    path(ax, [(410, 755), (450, 755)], color=TEAL)
    path(ax, [(1160, 755), (1200, 755)], color=ORANGE)
    save(fig, "figure-1-process-boundary")


def fig2():
    fig, ax = canvas(2, "两条派生链与一棵广播树", "管控与业务分源派生；广播树只负责纪元随机数的覆盖分发。")
    for x, w, edge, fill in [(50, 460, TEAL, TEAL_SOFT),
                              (550, 460, ORANGE, ORANGE_SOFT),
                              (1050, 500, BLUE, BLUE_SOFT)]:
        p = FancyBboxPatch((x, 160), w, 760, boxstyle="round,pad=0.01,rounding_size=20",
                           linewidth=1.4, edgecolor=edge, facecolor=fill, alpha=0.65)
        ax.add_patch(p)
    centered(ax, 75, 177, 410, 63, "管控链 · 台区停在这一链", color=TEAL, fill=WHITE)
    centered(ax, 575, 177, 410, 63, "业务链 · 不到台区", color=ORANGE, fill=WHITE)
    centered(ax, 1075, 177, 450, 63, "广播树 · 根只在省级", color=BLUE, fill=WHITE)

    mgmt = ["mk_mgmt", "地市委托", "县密钥（注册槽，不是台区号 42）",
            "台区管控密钥", "管理种子", "认证时间树", "认证密钥 ＋ 控制密钥"]
    biz = ["mk_biz", "地市业务委托", "县业务密钥", "业务种子",
           "业务时间树", "业务密钥 ＋ 完成标签"]
    for i, label in enumerate(mgmt):
        y = 262 + i * 91
        centered(ax, 80, y, 400, 61, label, color=TEAL, fill=WHITE,
                 size=18 if i != 2 else 17)
        if i:
            path(ax, [(280, y - 30), (280, y)], color=TEAL, lw=1.7, mutation=15)
    for i, label in enumerate(biz):
        y = 269 + i * 105
        centered(ax, 580, y, 400, 63, label, color=ORANGE, fill=WHITE, size=18)
        if i:
            path(ax, [(780, y - 42), (780, y)], color=ORANGE, lw=1.7, mutation=15)

    centered(ax, 1180, 268, 245, 70, "省级广播树根", color=BLUE, fill=WHITE)
    centered(ax, 1083, 390, 190, 65, "地市 A 节点", color=BLUE, fill=WHITE, size=18)
    centered(ax, 1327, 390, 190, 65, "地市 B 节点", color=BLUE, fill=WHITE, size=18)
    path(ax, [(1240, 338), (1240, 363), (1178, 363), (1178, 390)], color=BLUE)
    path(ax, [(1365, 338), (1365, 363), (1422, 363), (1422, 390)], color=BLUE)
    centered(ax, 1083, 520, 434, 112,
             "县以上终端：单向打开密钥\n推不出地市树根", color=BLUE, fill=WHITE, size=17)
    path(ax, [(1178, 455), (1178, 520)], color=BLUE)
    centered(ax, 1083, 690, 434, 90, "县以内：路径密钥", color=BLUE, fill=WHITE, size=19)
    path(ax, [(1300, 632), (1300, 690)], color=BLUE)
    txt(ax, 1300, 850, "终端只打开覆盖自己的那条密文", 17, BLUE, "center")
    save(fig, "figure-2-derivation-broadcast")


def fig3():
    fig, ax = canvas(3, "灌装时序", "产线保有设备私钥；地市只封装两颗种子；省级单独封装 SM9 用户私钥。")
    participants = [(170, "省级软件模块", PURPLE), (570, "地市进程", TEAL),
                    (980, "产线进程", ORANGE), (1370, "终端", BLUE)]
    for x, label, color in participants:
        centered(ax, x - 145, 174, 290, 72, label, color=color, fill=WHITE, size=19)
        ax.plot([x, x], [246, 859], color=LINE, ls=(0, (5, 5)), lw=1.4)

    note(ax, 846, 253, 350, 68, "① 产线生成设备 SM2 密钥对", color=ORANGE,
         fill=ORANGE_SOFT, size=17, align="center")
    path(ax, [(980, 378), (570, 378)], color=ORANGE, lw=2.4)
    txt(ax, 775, 352, "只把设备公钥给地市", 18, ORANGE, "center", "bold")

    note(ax, 416, 417, 340, 75, "② 地市封装管理种子和业务种子\n自己不打开", color=TEAL,
         fill=TEAL_SOFT, size=16, align="center")
    path(ax, [(570, 548), (980, 548)], color=TEAL, lw=2.4)
    txt(ax, 775, 520, "两颗种子的封装", 18, TEAL, "center", "bold")

    note(ax, 22, 576, 350, 74, "③ SM9 用户私钥封给\n同一把设备公钥", color=PURPLE,
         fill=PURPLE_SOFT, size=17, align="center")
    path(ax, [(170, 709), (980, 709)], color=PURPLE, lw=2.4)
    txt(ax, 575, 681, "SM9 封装；明文不进地市", 18, PURPLE, "center", "bold")

    note(ax, 820, 729, 320, 65, "④ 产线在本地打开两份封装", color=ORANGE,
         fill=ORANGE_SOFT, size=16, align="center")
    path(ax, [(980, 842), (1370, 842)], color=ORANGE, lw=2.4)
    txt(ax, 1175, 816, "灌装到终端", 18, ORANGE, "center", "bold")
    note(ax, 45, 909, 1510, 58, "SM9 只用于接入认证，不进入后来的纪元报文。", color=PURPLE,
         fill=PURPLE_SOFT, size=20, align="center")
    save(fig, "figure-3-provisioning-sequence")


def fig4():
    fig, ax = canvas(4, "纪元覆盖与终端打开", "同一份签名广播；空吊销和非空吊销只有一个分支判断。")
    centered(ax, 600, 158, 400, 75, "发布新纪元", color=PURPLE, fill=PURPLE_SOFT, size=23)
    path(ax, [(800, 233), (800, 264)], color=PURPLE)
    diamond = Polygon([(800, 265), (1000, 348), (800, 431), (600, 348)],
                      closed=True, facecolor=WHITE, edgecolor=PURPLE, linewidth=2)
    ax.add_patch(diamond)
    txt(ax, 800, 348, "吊销集为空？", 22, PURPLE, "center", "bold")

    box(ax, 90, 480, 550, 134, "是 → 完全子树", ["节点 1：只发一条根密文"],
        color=TEAL, fill=TEAL_SOFT, title_size=23, body_size=19, body_start=566)
    box(ax, 960, 480, 550, 134, "否 → 子集差", ["整区、整县、整批各自一条密文"],
        color=ORANGE, fill=ORANGE_SOFT, title_size=23, body_size=19, body_start=566)
    path(ax, [(630, 366), (365, 366), (365, 480)], color=TEAL)
    path(ax, [(970, 366), (1235, 366), (1235, 480)], color=ORANGE)

    centered(ax, 560, 655, 480, 83, "制作条目 Merkle 根与证明", color=BLUE,
             fill=BLUE_SOFT, size=21)
    path(ax, [(365, 614), (365, 636), (800, 636), (800, 655)], color=TEAL)
    path(ax, [(1235, 614), (1235, 636), (800, 636), (800, 655)], color=ORANGE)

    centered(ax, 65, 785, 440, 88, "终端先验 SM2", color=PURPLE, fill=PURPLE_SOFT, size=21)
    centered(ax, 580, 785, 440, 88, "再核对自己的那一条", color=BLUE, fill=BLUE_SOFT, size=21)
    centered(ax, 1095, 785, 440, 88, "最后打开随机数", color=TEAL, fill=TEAL_SOFT, size=21)
    path(ax, [(800, 738), (800, 758), (285, 758), (285, 785)], color=BLUE)
    path(ax, [(505, 829), (580, 829)], color=BLUE)
    path(ax, [(1020, 829), (1095, 829)], color=BLUE)
    txt(ax, 800, 904, "漏掉的中间纪元不用补装。", 18, TEAL, "center", "bold")
    note(ax, 83, 932, 1434, 52,
         "对照：逐台 SM2 加密下发，百万台约 1.8 小时（仓库参考测量）；这里百万台是同一份广播上的对称计算。",
         color=ORANGE, fill=ORANGE_SOFT, size=17, align="center")
    save(fig, "figure-4-epoch-cover")


def fig5():
    fig, ax = canvas(5, "分级加密与确认", "终端解开纪元后分成电能量、控制和确认三路。")
    centered(ax, 560, 160, 480, 80, "终端打开纪元随机数", color=PURPLE,
             fill=PURPLE_SOFT, size=22)
    ax.plot([800, 800], [240, 278], color=LINE, lw=2)
    ax.plot([280, 1310], [278, 278], color=LINE, lw=2)
    for x in [280, 790, 1310]:
        path(ax, [(x, 278), (x, 312)], color=LINE)

    box(ax, 55, 312, 450, 305, "电能量 · 业务密钥", [
        "终端用业务密钥加密电能量", "台区打开失败", "省级可以解开明文",
    ], color=ORANGE, fill=ORANGE_SOFT, title_size=21, body_size=18,
        body_start=410, line_height=56)
    note(ax, 82, 676, 395, 116, "业务种子不下发台区\n业务明文只由省级打开",
         color=ORANGE, fill=WHITE, size=17, align="center")

    box(ax, 565, 312, 450, 305, "控制 · 控制密钥", [
        "终端用控制密钥加密", "台区可以打开", "省级也可以打开",
    ], color=TEAL, fill=TEAL_SOFT, title_size=21, body_size=18,
        body_start=410, line_height=56)
    note(ax, 592, 676, 395, 116, "台区只停在管控链\n仍能处理控制业务",
         color=TEAL, fill=WHITE, size=17, align="center")

    centered(ax, 1070, 312, 470, 93, "终端：业务密钥出 16 字节标签",
             color=PURPLE, fill=PURPLE_SOFT, size=18)
    centered(ax, 1070, 444, 470, 93, "台区：只做异或 → 完成帧 62 字节",
             color=PURPLE, fill=PURPLE_SOFT, size=18)
    centered(ax, 1070, 576, 470, 93, "省级：用业务主密钥重算",
             color=PURPLE, fill=PURPLE_SOFT, size=18)
    box(ax, 1070, 708, 470, 115, "一致 → 记已确认", ["不一致 → 拒绝；吊销集不变"],
        color=PURPLE, fill=PURPLE_SOFT, title_size=18, body_size=17, body_start=785)
    for y in [405, 537, 669]:
        path(ax, [(1305, y), (1305, y + 39)], color=PURPLE)
    note(ax, 65, 897, 1470, 74,
         "台区没有业务种子，伪造不了这 62 字节完成帧；确认失败只记未跟上，不自动吊销。",
         color=RED, fill=RED_SOFT, size=19, align="center")
    save(fig, "figure-5-graded-confirmation")


def fig6():
    fig, ax = canvas(6, "叶子的归宿", "生命周期状态图：区分吊销、换表、割接、销毁、召回与确认失败。")
    centered(ax, 45, 470, 320, 140, "在册叶子", color=BLUE,
             fill=BLUE_SOFT, size=26)
    ax.plot([365, 435], [540, 540], color=BLUE, lw=2.2)
    ax.plot([435, 435], [214, 924], color=BLUE, lw=2.2)

    rows = [
        (170, 108, "吊销", "叶子进入吊销集；解不开新纪元；槽位不回收。", RED, RED_SOFT),
        (300, 108, "换表", "旧叶子吊销；新设备取得新叶子。", ORANGE, ORANGE_SOFT),
        (430, 108, "割接", "旧叶子吊销；同一把设备公钥；新台区重新派生业务种子。", ORANGE, ORANGE_SOFT),
        (560, 155, "销毁", "叶子不进吊销集；产线丢掉设备私钥；不能割接或重新灌装。\n旧的 SM9 签名仍可公开核验。", PURPLE, PURPLE_SOFT),
        (737, 108, "固件召回", "整批进入吊销集，包含还没分配的槽。", RED, RED_SOFT),
        (867, 108, "确认失败", "只记未跟上；不进入吊销态。", MUTED, GREY_SOFT),
    ]
    for y, h, label, detail, color, fill in rows:
        path(ax, [(435, y + h / 2), (520, y + h / 2)], color=color,
             style="dashed" if label == "确认失败" else "solid")
        box(ax, 520, y, 1030, h, label, detail.split("\n"), color=color,
            fill=fill, title_size=21, body_size=17, body_start=y + 74,
            line_height=32)
    save(fig, "figure-6-leaf-lifecycle")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for make in [fig1, fig2, fig3, fig4, fig5, fig6]:
        make()
    print(f"Rendered six SVG and six PNG diagrams in {OUT}")
