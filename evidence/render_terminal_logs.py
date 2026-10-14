"""Render captured command logs as readable, provenance-labelled PNG evidence.

The terminal body is copied from evidence/logs without changing its text.
This script does not run the benchmarks or synthesize command output.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
LOGS = ROOT / "logs"
SHOTS = ROOT / "screenshots"
FONT = "/System/Library/Fonts/STHeiti Medium.ttc"


def lines(name: str) -> list[str]:
    return (LOGS / name).read_text(encoding="utf-8").splitlines()


bench = lines("make-bench.txt")
test = lines("make-test.txt")
demo = lines("make-demo.txt")
split = lines("make-split.txt")
processes = lines("ps-grid-epoch.txt")

shots = [
    ("01-make-bench.png", "make bench", "make-bench.txt", bench, "完整输出；数据来自这台机器的实测"),
    ("02-make-test-ok.png", "make test", "make-test.txt", test[-13:], "原始输出末尾；完整日志另存"),
    ("07-make-demo-1-3.png", "make demo  /  步骤 1—3", "make-demo.txt", demo[:14], "原始输出节选：纪元 0、分级认证与分级加密"),
    ("08-make-demo-4.png", "make demo  /  步骤 4", "make-demo.txt", [demo[14]], "原始输出节选：离线直达"),
    ("09-make-split-1.png", "make split  /  步骤 1", "make-split.txt", split[:2], "原始输出节选：漏掉纪元 1 后直达纪元 2"),
    ("10-make-split-2-3.png", "make split  /  步骤 2—3", "make-split.txt", split[2:], "原始输出节选：吊销与换表"),
    ("11-five-processes.png", "ps aux | grep grid_epoch", "ps-grid-epoch.txt", processes, "进程运行期间的原始 ps 输出；五个服务同时在列"),
]


def render(filename: str, title: str, source: str, body: list[str], note: str) -> dict:
    body_font = ImageFont.truetype(FONT, 31)
    title_font = ImageFont.truetype(FONT, 44)
    meta_font = ImageFont.truetype(FONT, 24)
    line_height = 47
    pad_x = 62
    left_gutter = 26

    measure = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    widest = max((measure.textlength(row, font=body_font) for row in body), default=0)
    width = max(1650, min(4250, int(widest + pad_x * 2 + left_gutter)))
    # Each row remains unwrapped, so the image preserves the captured text.
    height = 205 + max(4, len(body)) * line_height + 76
    img = Image.new("RGB", (width, height), "#0a1020")
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((20, 20, width - 20, height - 20), radius=25, fill="#111a2b", outline="#30405a", width=2)
    d.rounded_rectangle((22, 22, width - 22, 88), radius=24, fill="#1b2940")
    d.rectangle((22, 63, width - 22, 88), fill="#1b2940")
    for x, color in ((58, "#fb645f"), (82, "#f6c453"), (106, "#54c47f")):
        d.ellipse((x, 50, x + 14, 64), fill=color)
    d.text((pad_x, 109), title, font=title_font, fill="#eaf3ff")
    d.text((pad_x, 169), f"原始日志  evidence/logs/{source}", font=meta_font, fill="#8ca2be")
    y = 218
    for row in body:
        is_key = any(token in row for token in ("1000 万台", "100 万台", "千万台", "百万台", "62 字节", "1.8 小时", "4 个进程", "OK", "纪元 0", "漏掉纪元", "TerminalRevoked", "grid_epoch."))
        color = "#bfead5" if is_key else "#e2e9f4"
        d.text((pad_x, y), row, font=body_font, fill=color)
        y += line_height
    d.line((pad_x, height - 72, width - pad_x, height - 72), fill="#30405a", width=1)
    d.text((pad_x, height - 61), note, font=meta_font, fill="#8ca2be")
    SHOTS.mkdir(parents=True, exist_ok=True)
    out = SHOTS / filename
    img.save(out, optimize=True)
    return {
        "file": str(out.relative_to(ROOT)),
        "source": str((LOGS / source).relative_to(ROOT)),
        "source_sha256": hashlib.sha256((LOGS / source).read_bytes()).hexdigest(),
        "included_lines": body,
        "note": note,
    }


manifest_path = ROOT / "terminal-manifest.json"
if len(sys.argv) == 3 and sys.argv[1] == "--only":
    target = sys.argv[2]
    existing = json.loads(manifest_path.read_text(encoding="utf-8"))
    replacement = next(render(*shot) for shot in shots if shot[0] == target)
    manifest = [replacement if item["file"] == replacement["file"] else item for item in existing]
    print(replacement["file"])
else:
    manifest = [render(*shot) for shot in shots]
    print("\n".join(item["file"] for item in manifest))
manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
