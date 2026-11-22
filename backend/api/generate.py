import json
import os
import sys
import urllib.parse
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

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(raw_body.decode("utf-8"))
            text = str(data.get("text", ""))
            title = str(data.get("title", "Handschrift")).strip() or "Handschrift"

            if not text.strip():
                err = json.dumps({"error": "Text darf nicht leer sein."}).encode("utf-8")
                self.send_response(400)
                _cors_headers(self)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(err)))
                self.end_headers()
                self.wfile.write(err)
                return

            eng = get_engine()
            archive_bytes, stats = eng.generate(text=text, title=title)

            missing_hdr = urllib.parse.quote(json.dumps(stats["missing_chars"], ensure_ascii=False))
            self.send_response(200)
            _cors_headers(self)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="handschrift.goodnotes"')
            self.send_header("Content-Length", str(len(archive_bytes)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Missing-Chars", missing_hdr)
            self.send_header("X-Page-Count", str(stats["pages"]))
            self.send_header("X-Glyph-Count", str(stats["total_glyphs"]))
            self.end_headers()
            self.wfile.write(archive_bytes)
        except Exception as e:
            err = json.dumps({"error": str(e)}).encode("utf-8")
            self.send_response(500)
            _cors_headers(self)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(err)))
            self.end_headers()
            self.wfile.write(err)
