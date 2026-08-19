from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .engine import WazuhAnalysisEngine

MAX_BODY = 64 * 1024 * 1024
ENGINE = WazuhAnalysisEngine()
ALLOWED_ORIGINS = {
    "http://127.0.0.1:8080", "http://localhost:8080",
    "http://127.0.0.1:8765", "http://localhost:8765",
    "https://shalvalekishvili.github.io",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "DolosBlackMagicWazuh/1.0"

    def _origin(self) -> str:
        return self.headers.get("Origin", "")

    def _cors(self) -> None:
        origin = self._origin()
        if origin in ALLOWED_ORIGINS or origin.startswith("http://127.0.0.1:") or origin.startswith("http://localhost:"):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-DBM-Client")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Cache-Control", "no-store")

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if urlparse(self.path).path == "/health":
            self._json(200, {"ok": True, "engine": ENGINE.VERSION, "name": "DolosBlackMagic Python Wazuh Engine"})
            return
        self._json(404, {"ok": False, "error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/analyze":
            self._json(404, {"ok": False, "error": "Not found"})
            return
        origin = self._origin()
        if origin and not (origin in ALLOWED_ORIGINS or origin.startswith("http://127.0.0.1:") or origin.startswith("http://localhost:")):
            self._json(403, {"ok": False, "error": "Origin not allowed"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"ok": False, "error": "Invalid Content-Length"})
            return
        if length <= 0:
            self._json(400, {"ok": False, "error": "Request body is empty"})
            return
        if length > MAX_BODY:
            self._json(413, {"ok": False, "error": "Payload exceeds 64 MB local-engine limit"})
            return
        raw = self.rfile.read(length)
        try:
            ctype = self.headers.get("Content-Type", "")
            if "application/json" in ctype:
                envelope = json.loads(raw.decode("utf-8"))
                payload = envelope.get("payload", "") if isinstance(envelope, dict) else envelope
                if not isinstance(payload, str):
                    payload = json.dumps(payload, ensure_ascii=False)
            else:
                payload = raw.decode("utf-8", errors="replace")
            result = ENGINE.analyze(payload)
            self._json(200, {"ok": True, "result": result})
        except Exception as exc:  # defensive HTTP boundary
            self._json(400, {"ok": False, "error": f"Analysis failed safely: {type(exc).__name__}: {exc}"})

    def log_message(self, fmt: str, *args) -> None:
        print(f"[dbm-wazuh] {self.address_string()} - {fmt % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="DolosBlackMagic local Python Wazuh analysis service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"DolosBlackMagic Python Wazuh Engine listening on http://{args.host}:{args.port}")
    print("No telemetry leaves this machine. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
