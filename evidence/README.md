# 衍枢 GridEpoch：本地运行与答辩证据

源码基线：`9b81fbd117f58798440d51bc708e02e9448bd3b0`；本目录对应本地修正与 2026-10-08 的实跑。

先执行 `python3 -m venv .venv`、`.venv/bin/pip install -r requirements.txt`。运行 `make bench` 生成 `bench/last_result.json`，再启动 `make console`，访问 `http://127.0.0.1:8765`。`make test` 现在也可在没有基准结果文件时独立通过。截图时值班台已在基准后重启。

## 按答辩顺序的截图

- [01-make-bench — 完整输出；数据来自这台机器的实测](screenshots/01-make-bench.png)
- [02-make-test-ok — 原始输出末尾；完整日志另存](screenshots/02-make-test-ok.png)
- [03-console-footer — 重启后的本机基准页脚](screenshots/03-console-footer.png)
- [04-unpublished — 发布前：三台区各四台，未下发](screenshots/04-unpublished.png)
- [05-published — 纪元1：完全子树与三份SM2验签](screenshots/05-published.png)
- [06-confirm-all — 台区42四台确认，43与44未下发](screenshots/06-confirm-all.png)
- [07-make-demo-1-3 — 原始输出节选：纪元 0、分级认证与分级加密](screenshots/07-make-demo-1-3.png)
- [08-make-demo-4 — 原始输出节选：离线直达](screenshots/08-make-demo-4.png)
- [09-make-split-1 — 原始输出节选：漏掉纪元 1 后直达纪元 2](screenshots/09-make-split-1.png)
- [10-make-split-2-3 — 原始输出节选：吊销与换表](screenshots/10-make-split-2-3.png)
- [11-five-processes — 进程运行期间的原始 ps 输出；五个服务同时在列](screenshots/11-five-processes.png)
- [12-password-wrong — 错一份口令：核对失败](screenshots/12-password-wrong.png)
- [13-password-correct — 两份口令核对通过](screenshots/13-password-correct.png)
- [14-epoch-escrow — 纪元1托管打开，不返回随机数](screenshots/14-epoch-escrow.png)
- [15-drop-expired — 当前仍是纪元1，没有更早纪元可丢](screenshots/15-drop-expired.png)
- [16-sm9-enrollment — 在册终端接入通过，页眉仍是纪元1](screenshots/16-sm9-enrollment.png)
- [17-confirm-withheld — 扣下序号1：确认失败不吊销](screenshots/17-confirm-withheld.png)
- [18-revoke-sd — 单台吊销：切换子集差](screenshots/18-revoke-sd.png)
- [19-watch — 观察名单只有未下发台区](screenshots/19-watch.png)
- [20-replace — 换表：新设备与新叶子](screenshots/20-replace.png)
- [21-transfer — 割接到新台区45，使用新序号5](screenshots/21-transfer.png)
- [22-destroy — 销毁：叶子保留，在册减少](screenshots/22-destroy.png)
- [23-destroy-lookup — 销毁后查询：结果行已销毁](screenshots/23-destroy-lookup.png)
- [24-destroy-enrollment-rejected — 销毁后接入被拒绝](screenshots/24-destroy-enrollment-rejected.png)
- [25-destroy-transfer-rejected — 销毁后割接被拒绝](screenshots/25-destroy-transfer-rejected.png)
- [26-destroy-reprovision-rejected — 销毁后重新灌装被拒绝](screenshots/26-destroy-reprovision-rejected.png)
- [27-archive-audit — 归档更早审计，热表留最新一条](screenshots/27-archive-audit.png)
- [28-revoke-gateway — 网关换槽，管控密钥未轮换](screenshots/28-revoke-gateway.png)
- [29-reprovision — 在册终端重新灌装，管理种子一致](screenshots/29-reprovision.png)
- [30-recall-last — 最后一步：召回固件1](screenshots/30-recall-last.png)

## 六张可编辑答辩图

- 进程和密钥边界：[PNG](diagrams/figure-1-process-boundary.png) · [SVG](diagrams/figure-1-process-boundary.svg)
- 两条派生链和广播树：[PNG](diagrams/figure-2-derivation-broadcast.png) · [SVG](diagrams/figure-2-derivation-broadcast.svg)
- 灌装时序：[PNG](diagrams/figure-3-provisioning-sequence.png) · [SVG](diagrams/figure-3-provisioning-sequence.svg)
- 纪元覆盖和终端打开：[PNG](diagrams/figure-4-epoch-cover.png) · [SVG](diagrams/figure-4-epoch-cover.svg)
- 分级加密和确认：[PNG](diagrams/figure-5-graded-confirmation.png) · [SVG](diagrams/figure-5-graded-confirmation.svg)
- 叶子的归宿：[PNG](diagrams/figure-6-leaf-lifecycle.png) · [SVG](diagrams/figure-6-leaf-lifecycle.svg)

## 原始证据与口径

- [make bench 全输出](logs/make-bench.txt)；[本机结构化结果](logs/last_result.json)。终端树每台区 2048 槽，基准只抽每台区 100 台；1000 万台派生与百万台更新都是单机吞吐。
- [make test 全输出](logs/make-test.txt)：43 项测试，末尾 `OK`；已验证没有基准文件也能通过。
- [make demo](logs/make-demo.txt)、[make split](logs/make-split.txt) 与 [五进程原始 ps 输出](logs/ps-grid-epoch.txt)。终端风格图片按日志原文渲染，分段截图有明确标注，未改写测量值。
- 逐台 SM2 下发：本机本次估算约 1.4 小时；仓库此前参考测量约 1.8 小时。两数在 `make bench` 图片上分别标明，不能混称一次实测。
- [值班台截图状态清单](manifest.json) 与 [终端图片日志 SHA 清单](terminal-manifest.json) 可核对图片来源。
- 值班台截图是本地页面真实操作生成。页面只显示验签/托管结果；图片不含口令明文、随机数或第三份分片。

本地对原仓库的修正另存为 [local-changes.patch](local-changes.patch)，便于复核与重放。
