import json
import os
import sys
from http.server import BaseHTTPRequestHandler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from text_to_goodnotes import HandwritingEngine

_ENGINE = None


def get_engine() -> HandwritingEngine:
    global _ENGINE
    if _ENGINE is None:
        data_dir = os.path.join(ROOT, "data")
        _ENGINE = HandwritingEngine.from_files(
            os.path.join(data_dir, "glyph_bank.json"),
            os.path.join(data_dir, "a4_white_template.pdf"),
            os.path.join(data_dir, "a4_white_thumb.jpg"),
        )
    return _ENGINE


def _cors_headers(h: BaseHTTPRequestHandler):
    h.send_header("Access-Control-Allow-Origin", "*")
    h.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    h.send_header("Access-Control-Allow-Headers", "Content-Type")
    h.send_header("Access-Control-Expose-Headers", "X-Missing-Chars, X-Page-Count, X-Glyph-Count, Content-Disposition")


class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        _cors_headers(self)
        self.end_headers()

    def do_GET(self):
        try:
            eng = get_engine()
            payload = {
                "ok": True,
                "glyph_count": len(eng.available_keys()),
                "available_keys": eng.available_keys(),
            }
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            _cors_headers(self)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            body = json.dumps({"ok": False, "error": str(e)}).encode("utf-8")
            self.send_response(500)
            _cors_headers(self)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
