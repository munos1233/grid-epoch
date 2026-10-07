"""本机一页值班台。页面只跟同一套 ProvincialKMC 说话。"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .custodian import open_share_sink
from .desk import OperatorDesk
from .errors import AuthFailed, ProtocolError


PAGE = Path(__file__).with_name("console.html").read_text(encoding="utf-8")
_BENCH_PATH = Path(__file__).resolve().parent.parent / "bench" / "last_result.json"


def load_bench(path: Path = _BENCH_PATH) -> dict | None:
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        "terminal": int(data["package_bytes"]),
        "gateway": int(data["gateway_package_bytes"]),
        "revocation": int(data["revocation_bytes"]),
        "confirm_bytes": int(data["confirm_bytes_per_zone"]),
        "confirm_seconds": f"{float(data['confirm_update_seconds']):.3f}",
    }


def serve(directory: str | Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    sink, offline_dir = open_share_sink()
    if not offline_dir.is_dir():
        sink.close()
        raise ProtocolError("保管进程没有留下目录")
    desk = OperatorDesk(directory, sink=sink)
    desk.seal("值班甲", "值班乙")
    bench = load_bench()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/":
                self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
                return
            if path == "/api/status":
                body = desk.status()
                body["bench"] = bench
                self._json(body)
                return
            if path == "/api/zones":
                query = parse_qs(urlparse(self.path).query)
                page = int(query.get("page", ["0"])[0])
                self._json(desk.zones(page))
                return
            if path == "/api/members":
                query = parse_qs(urlparse(self.path).query)
                zone = int(query.get("zone", ["0"])[0])
                self._json(desk.members(zone))
                return
            if path == "/api/audit":
                self._json(desk.audit_tail())
                return
            self._json({"error": "没有这个页面"}, 404)

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            try:
                payload = self._payload()
                if path == "/api/publish":
                    self._json(desk.publish(str(payload["password_a"]), str(payload["password_b"])))
                elif path == "/api/lookup":
                    found = desk.lookup(int(payload["zone"]), int(payload["local_index"]))
                    self._json(found or {"error": "没有这台终端"}, 200 if found else 404)
                elif path == "/api/revoke":
                    self._json(desk.revoke(int(payload["zone"]), int(payload["local_index"])))
                elif path == "/api/replace":
                    self._json(desk.replace_meter(int(payload["zone"]), int(payload["local_index"]), int(payload["new_local"])))
                elif path == "/api/transfer":
                    self._json(
                        desk.transfer_meter(
                            int(payload["zone"]),
                            int(payload["local_index"]),
                            int(payload["new_zone"]),
                            int(payload["new_local"]),
                        )
                    )
                elif path == "/api/drop-expired":
                    self._json(desk.drop_expired())
                elif path == "/api/recover-epoch":
                    self._json(desk.recover_epoch(int(payload["epoch"]), str(payload["password_a"]), str(payload["password_b"])))
                elif path == "/api/destroy":
                    self._json(desk.destroy_meter(int(payload["zone"]), int(payload["local_index"])))
                elif path == "/api/archive-audit":
                    self._json(desk.archive_audit(int(payload["before_id"])))
                elif path == "/api/recall-firmware":
                    self._json(desk.recall_firmware(int(payload["zone"]), int(payload["version"])))
                elif path == "/api/revoke-gateway":
                    self._json(desk.revoke_gateway(int(payload["zone"])))
                elif path == "/api/reprovision":
                    self._json(desk.reprovision(int(payload["zone"]), int(payload["local_index"])))
                elif path == "/api/restore":
                    desk.restore(str(payload["password_a"]), str(payload["password_b"]))
                    self._json({"ok": True})
                elif path == "/api/enroll-check":
                    self._json(desk.check_enrollment(int(payload["zone"]), int(payload["local_index"])))
                elif path == "/api/confirm":
                    raw = payload.get("withhold")
                    withhold = None if raw in (None, "") else int(raw)
                    self._json(desk.confirm_zone(int(payload["zone"]), withhold))
                elif path == "/api/watch":
                    self._json(desk.note_watch())
                else:
                    self._json({"error": "没有这个操作"}, 404)
            except (AuthFailed, ProtocolError, KeyError, ValueError, FileNotFoundError) as exc:
                self._json({"error": str(exc)}, 400)

        def log_message(self, fmt: str, *args) -> None:
            return

        def _payload(self) -> dict:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}

        def _json(self, body, code: int = 200) -> None:
            encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self._send(code, encoded, "application/json; charset=utf-8")

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class SerializedServer(ThreadingHTTPServer):
        def __init__(self, address, handler) -> None:
            super().__init__(address, handler)
            self._request_lock = threading.Lock()

        def process_request(self, request, client_address) -> None:
            with self._request_lock:
                self.finish_request(request, client_address)
                self.shutdown_request(request)

    server = SerializedServer((host, port), Handler)
    print(f"值班台 http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        desk.close()
        server.server_close()


def main() -> None:
    serve(Path("bench") / "console_state")


if __name__ == "__main__":
    main()
