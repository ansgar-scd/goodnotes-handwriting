"""
Goodnotes 6 (.goodnotes) Parser & Generator Library.

Pure-Python implementation of the Goodnotes 6 binary format:
- ZIP container & delimited Protobuf streams (schema version 24)
- Apple bv41 (LZ4 raw block) compression & decompression
- TPL binary stroke serialization: vuA(v)A(S(uu))A(S(uuuu))vA(f)
- Consistent UUID, CRDT clock, event log, and thumbnail generation
"""

from __future__ import annotations

import io
import os
import random
import struct
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# =============================================================================
# 1. Protobuf Wire-Format Primitives (Zero External Dependencies)
# =============================================================================

def encode_varint(value: int) -> bytes:
    if value < 0:
        value &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def decode_varint(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("Truncated varint")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 70:
            raise ValueError("Varint overflow")


def pb_tag(field_num: int, wire_type: int) -> bytes:
    return encode_varint((field_num << 3) | wire_type)


def pb_varint(field_num: int, value: int, omit_zero: bool = True) -> bytes:
    if omit_zero and value == 0:
        return b""
    return pb_tag(field_num, 0) + encode_varint(value)


def pb_fixed32_float(field_num: int, value: float, omit_zero: bool = True) -> bytes:
    if omit_zero and value == 0.0:
        return b""
    return pb_tag(field_num, 5) + struct.pack("<f", value)


def pb_fixed64_double(field_num: int, value: float, omit_zero: bool = True) -> bytes:
    if omit_zero and value == 0.0:
        return b""
    return pb_tag(field_num, 1) + struct.pack("<d", value)


def pb_bytes(field_num: int, data: bytes, omit_empty: bool = False) -> bytes:
    if omit_empty and len(data) == 0:
        return b""
    return pb_tag(field_num, 2) + encode_varint(len(data)) + data


def pb_string(field_num: int, text: str, omit_empty: bool = False) -> bytes:
    return pb_bytes(field_num, text.encode("utf-8"), omit_empty=omit_empty)


def pb_submsg(field_num: int, payload: bytes, omit_empty: bool = False) -> bytes:
    return pb_bytes(field_num, payload, omit_empty=omit_empty)


def encode_delimited(messages: List[bytes]) -> bytes:
    out = bytearray()
    for msg in messages:
        out.extend(encode_varint(len(msg)))
        out.extend(msg)
    return bytes(out)


def decode_delimited(data: bytes) -> List[bytes]:
    pos = 0
    msgs: List[bytes] = []
    n = len(data)
    while pos < n:
        length, pos = decode_varint(data, pos)
        if pos + length > n:
            raise ValueError(f"Truncated delimited message at offset {pos}")
        msgs.append(data[pos : pos + length])
        pos += length
    return msgs


def parse_proto(data: bytes) -> List[Tuple[int, int, object]]:
    """Parse raw protobuf bytes into a list of (field_num, wire_type, value)."""
    pos = 0
    n = len(data)
    fields: List[Tuple[int, int, object]] = []
    while pos < n:
        tag, pos = decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if wire_type == 0:
            val, pos = decode_varint(data, pos)
            fields.append((field_num, 0, val))
        elif wire_type == 1:
            raw = data[pos : pos + 8]
            pos += 8
            fields.append((field_num, 1, raw))
        elif wire_type == 2:
            length, pos = decode_varint(data, pos)
            raw = data[pos : pos + length]
            pos += length
            fields.append((field_num, 2, raw))
        elif wire_type == 5:
            raw = data[pos : pos + 4]
            pos += 4
            fields.append((field_num, 5, raw))
        else:
            raise ValueError(f"Unsupported wire type {wire_type}")
    return fields


def get_field(fields: List[Tuple[int, int, object]], num: int, default=None):
    for fn, _wt, val in fields:
        if fn == num:
            return val
    return default


# =============================================================================
# 2. Apple bv41 (LZ4 Raw Block) Compression & Decompression
# =============================================================================

def lz4_decompress_block(src: bytes, uncompressed_size: int) -> bytes:
    out = bytearray()
    i = 0
    n = len(src)
    while i < n:
        token = src[i]
        i += 1
        lit_len = token >> 4
        if lit_len == 15:
            while True:
                b = src[i]
                i += 1
                lit_len += b
                if b != 255:
                    break
        out.extend(src[i : i + lit_len])
        i += lit_len
        if i >= n:
            break
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0:
            raise ValueError("Invalid LZ4 match offset 0")
        match_len = (token & 0x0F) + 4
        if (token & 0x0F) == 15:
            while True:
                b = src[i]
                i += 1
                match_len += b
                if b != 255:
                    break
        start = len(out) - offset
        for k in range(match_len):
            out.append(out[start + k])
    if len(out) != uncompressed_size:
        raise ValueError(f"LZ4 size mismatch: expected {uncompressed_size}, got {len(out)}")
    return bytes(out)


def lz4_compress_block(src: bytes) -> bytes:
    """Standard LZ4 raw block compressor (compatible with Apple Compression framework)."""
    n = len(src)
    out = bytearray()
    if n == 0:
        return b""

    hash_table: Dict[bytes, int] = {}
    anchor = 0
    i = 0
    # LZ4 spec: last 5 bytes must be literals, last match must start <= n - 12
    limit = n - 12

    while i <= limit:
        seq = src[i : i + 4]
        prev = hash_table.get(seq)
        hash_table[seq] = i
        if prev is not None and 0 < (i - prev) <= 65535 and src[prev : prev + 4] == seq:
            offset = i - prev
            # Extend match up to n - 5
            match_len = 4
            max_match = (n - 5) - i
            while match_len < max_match and src[prev + match_len] == src[i + match_len]:
                match_len += 1

            lit_len = i - anchor
            ml_code = match_len - 4
            token = (min(lit_len, 15) << 4) | min(ml_code, 15)
            out.append(token)
            if lit_len >= 15:
                rem = lit_len - 15
                while rem >= 255:
                    out.append(255)
                    rem -= 255
                out.append(rem)
            out.extend(src[anchor:i])
            out.append(offset & 0xFF)
            out.append((offset >> 8) & 0xFF)
            if ml_code >= 15:
                rem = ml_code - 15
                while rem >= 255:
                    out.append(255)
                    rem -= 255
                out.append(rem)

            i += match_len
            anchor = i
        else:
            i += 1

    # Emit final literals
    lit_len = n - anchor
    token = min(lit_len, 15) << 4
    out.append(token)
    if lit_len >= 15:
        rem = lit_len - 15
        while rem >= 255:
            out.append(255)
            rem -= 255
        out.append(rem)
    out.extend(src[anchor:n])
    return bytes(out)


def bv41_decompress(data: bytes) -> bytes:
    pos = 0
    out = bytearray()
    while pos < len(data):
        magic = data[pos : pos + 4]
        if magic == b"bv4$":
            break
        elif magic == b"bv41":
            uncomp_sz, comp_sz = struct.unpack("<II", data[pos + 4 : pos + 12])
            pos += 12
            block = data[pos : pos + comp_sz]
            pos += comp_sz
            out.extend(lz4_decompress_block(block, uncomp_sz))
        elif magic == b"bv4-":
            uncomp_sz = struct.unpack("<I", data[pos + 4 : pos + 8])[0]
            pos += 8
            out.extend(data[pos : pos + uncomp_sz])
            pos += uncomp_sz
        else:
            raise ValueError(f"Unknown bv4 magic {magic!r} at offset {pos}")
    return bytes(out)


def bv41_compress(data: bytes) -> bytes:
    comp = lz4_compress_block(data)
    return b"bv41" + struct.pack("<II", len(data), len(comp)) + comp + b"bv4$"


# =============================================================================
# 3. TPL Stroke Serialization: vuA(v)A(S(uu))A(S(uuuu))vA(f)
# =============================================================================

TPL_STROKE_FMT = "vuA(v)A(S(uu))A(S(uuuu))vA(f)"


@dataclass
class ColorRGBA:
    r: float = 0.0
    g: float = 0.0
    b: float = 0.0
    a: float = 1.0

    def to_proto(self) -> bytes:
        return (
            pb_fixed32_float(1, self.r, omit_zero=True)
            + pb_fixed32_float(2, self.g, omit_zero=True)
            + pb_fixed32_float(3, self.b, omit_zero=True)
            + pb_fixed32_float(4, self.a, omit_zero=True)
        )

    @classmethod
    def from_proto(cls, data: bytes) -> "ColorRGBA":
        fields = parse_proto(data)
        def _f(num: int) -> float:
            raw = get_field(fields, num)
            return struct.unpack("<f", raw)[0] if raw is not None else 0.0
        return cls(_f(1), _f(2), _f(3), _f(4))


@dataclass
class StrokeGeometry:
    """Decoded TPL stroke geometry in Goodnotes canvas coordinates (origin top-left)."""
    version: int = 2
    width: float = 2.078740119934082
    ops: List[int] = field(default_factory=list)               # 0 = MoveTo, 1 = QuadCurveTo
    moves: List[Tuple[float, float]] = field(default_factory=list)
    quads: List[Tuple[float, float, float, float]] = field(default_factory=list)  # (cx, cy, ex, ey)
    style: int = 1
    pressures: List[float] = field(default_factory=list)

    def translate(self, dx: float, dy: float) -> "StrokeGeometry":
        return StrokeGeometry(
            version=self.version,
            width=self.width,
            ops=list(self.ops),
            moves=[(x + dx, y + dy) for (x, y) in self.moves],
            quads=[(cx + dx, cy + dy, ex + dx, ey + dy) for (cx, cy, ex, ey) in self.quads],
            style=self.style,
            pressures=list(self.pressures),
        )

    def scale(self, sx: float, sy: Optional[float] = None, origin: Tuple[float, float] = (0.0, 0.0)) -> "StrokeGeometry":
        if sy is None:
            sy = sx
        ox, oy = origin
        return StrokeGeometry(
            version=self.version,
            width=self.width * ((sx + sy) * 0.5),
            ops=list(self.ops),
            moves=[(ox + (x - ox) * sx, oy + (y - oy) * sy) for (x, y) in self.moves],
            quads=[
                (
                    ox + (cx - ox) * sx,
                    oy + (cy - oy) * sy,
                    ox + (ex - ox) * sx,
                    oy + (ey - oy) * sy,
                )
                for (cx, cy, ex, ey) in self.quads
            ],
            style=self.style,
            pressures=list(self.pressures),
        )

    def all_points(self) -> List[Tuple[float, float]]:
        pts = list(self.moves)
        for cx, cy, ex, ey in self.quads:
            pts.append((cx, cy))
            pts.append((ex, ey))
        return pts

    def bbox(self) -> Tuple[float, float, float, float]:
        """Return (min_x, min_y, max_x, max_y)."""
        pts = self.all_points()
        if not pts:
            return (0.0, 0.0, 0.0, 0.0)
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        return (min(xs), min(ys), max(xs), max(ys))

    def sample_polyline(self, steps_per_quad: int = 8) -> List[List[Tuple[float, float]]]:
        """Evaluate MoveTo + QuadCurveTo operations into polylines for rendering."""
        polylines: List[List[Tuple[float, float]]] = []
        current: List[Tuple[float, float]] = []
        m_idx = 0
        q_idx = 0
        cur_pt = (0.0, 0.0)
        for op in self.ops:
            if op == 0:
                if current:
                    polylines.append(current)
                cur_pt = self.moves[m_idx]
                m_idx += 1
                current = [cur_pt]
            elif op == 1:
                cx, cy, ex, ey = self.quads[q_idx]
                q_idx += 1
                x0, y0 = cur_pt
                for s in range(1, steps_per_quad + 1):
                    t = s / steps_per_quad
                    mt = 1.0 - t
                    px = mt * mt * x0 + 2.0 * mt * t * cx + t * t * ex
                    py = mt * mt * y0 + 2.0 * mt * t * cy + t * t * ey
                    current.append((px, py))
                cur_pt = (ex, ey)
        if current:
            polylines.append(current)
        return polylines

    def to_tpl_bytes(self) -> bytes:
        fmt_bytes = TPL_STROKE_FMT.encode("ascii") + b"\x00"
        payload = bytearray()
        payload.extend(struct.pack("<Hf", self.version, self.width))
        payload.extend(struct.pack("<I", len(self.ops)))
        if self.ops:
            payload.extend(struct.pack(f"<{len(self.ops)}H", *self.ops))
        payload.extend(struct.pack("<I", len(self.moves)))
        for x, y in self.moves:
            payload.extend(struct.pack("<ff", x, y))
        payload.extend(struct.pack("<I", len(self.quads)))
        for cx, cy, ex, ey in self.quads:
            payload.extend(struct.pack("<ffff", cx, cy, ex, ey))
        payload.extend(struct.pack("<H", self.style))
        payload.extend(struct.pack("<I", len(self.pressures)))
        if self.pressures:
            payload.extend(struct.pack(f"<{len(self.pressures)}d", *self.pressures))

        total_size = 4 + 4 + len(fmt_bytes) + len(payload)
        return b"tpl\x00" + struct.pack("<I", total_size) + fmt_bytes + bytes(payload)

    @classmethod
    def from_tpl_bytes(cls, raw: bytes) -> "StrokeGeometry":
        if raw[:3] != b"tpl":
            raise ValueError(f"Invalid TPL magic: {raw[:4]!r}")
        size = struct.unpack("<I", raw[4:8])[0]
        if size != len(raw):
            raise ValueError(f"TPL size mismatch: header={size}, actual={len(raw)}")
        nul = raw.index(0, 8)
        fmt = raw[8:nul].decode("ascii")
        if fmt != TPL_STROKE_FMT:
            raise ValueError(f"Unsupported TPL format: {fmt!r}")
        p = nul + 1
        version, width = struct.unpack("<Hf", raw[p : p + 6])
        p += 6
        n_ops = struct.unpack("<I", raw[p : p + 4])[0]
        p += 4
        ops = list(struct.unpack(f"<{n_ops}H", raw[p : p + 2 * n_ops]))
        p += 2 * n_ops
        n_moves = struct.unpack("<I", raw[p : p + 4])[0]
        p += 4
        moves = [struct.unpack("<ff", raw[p + 8 * i : p + 8 * (i + 1)]) for i in range(n_moves)]
        p += 8 * n_moves
        n_quads = struct.unpack("<I", raw[p : p + 4])[0]
        p += 4
        quads = [struct.unpack("<ffff", raw[p + 16 * i : p + 16 * (i + 1)]) for i in range(n_quads)]
        p += 16 * n_quads
        style = struct.unpack("<H", raw[p : p + 2])[0]
        p += 2
        n_p = struct.unpack("<I", raw[p : p + 4])[0]
        p += 4
        pressures = list(struct.unpack(f"<{n_p}d", raw[p : p + 8 * n_p]))
        p += 8 * n_p
        if p != len(raw):
            raise ValueError(f"TPL trailing bytes: {len(raw) - p}")
        return cls(
            version=version,
            width=width,
            ops=ops,
            moves=moves,
            quads=quads,
            style=style,
            pressures=pressures,
        )


@dataclass
class InkStroke:
    uid: str
    geometry: StrokeGeometry
    color: ColorRGBA = field(default_factory=ColorRGBA)
    z_index: int = 0
    deleted: bool = False


# =============================================================================
# 4. UUID & CRDT Helpers
# =============================================================================

def new_uuid() -> str:
    return str(uuid.uuid4()).upper()


def increment_uuid(uid_str: str, delta: int = 1) -> str:
    """
    Goodnotes 6 derives a page's note-layer UUID deterministically from its page UUID
    by incrementing the 128-bit integer value by 1:
        PAGE_UUID = ...79F1  -->  NOTE_UUID = ...79F2
    """
    val = (uuid.UUID(uid_str).int + delta) & ((1 << 128) - 1)
    return str(uuid.UUID(int=val)).upper()


def encode_lamport_clock(counter: int, tie_breaker: Optional[int] = None) -> bytes:
    if tie_breaker is None:
        tie_breaker = random.randint(1, 0xFFFFFFFF)
    return pb_varint(1, counter, omit_zero=True) + pb_varint(2, tie_breaker, omit_zero=False)


def encode_lww_string(value: str, counter: int = 1) -> bytes:
    return pb_string(1, value) + pb_submsg(2, encode_lamport_clock(counter))


def encode_lww_varint(value: int, counter: int = 1) -> bytes:
    return pb_varint(1, value, omit_zero=False) + pb_submsg(2, encode_lamport_clock(counter))


def encode_lww_double(value: float, counter: int = 1) -> bytes:
    return pb_fixed64_double(1, value, omit_zero=False) + pb_submsg(2, encode_lamport_clock(counter))


# =============================================================================
# 5. Reader & Writer for .goodnotes Archives
# =============================================================================

@dataclass
class GoodnotesPage:
    page_idx: int
    page_uuid: str
    note_uuid: str
    sort_key: str
    width: float
    height: float
    line_spacing: float
    y_start: float
    template_name: str
    strokes: List[InkStroke]


@dataclass
class GoodnotesDocument:
    title: str
    page_width: float
    page_height: float
    strokes: List[InkStroke]
    template_pdf: bytes
    template_name: str = "238EE861-EE9A-51BD-B010-832CD3C50D2C_a4_1_2 - White"
    base_thumbnail_jpg: Optional[bytes] = None
    doc_uuid: Optional[str] = None
    page_uuid: Optional[str] = None
    note_uuid: Optional[str] = None
    attachment_uuid: Optional[str] = None
    template_uuid: Optional[str] = None


def read_goodnotes_pages(path: str, include_deleted_pages: bool = False) -> Tuple[str, List[GoodnotesPage]]:
    """
    Parse all pages of a multi-page Goodnotes 6 .goodnotes archive.
    Returns (document_title, list_of_pages_sorted_by_sort_key).
    """
    with zipfile.ZipFile(path, "r") as zf:
        names = set(zf.namelist())
        events = decode_delimited(zf.read("index.events.pb"))

        title = os.path.splitext(os.path.basename(path))[0]
        templates: Dict[str, dict] = {}
        pages_meta: Dict[str, dict] = {}
        deleted_pages: set = set()

        for ev in events:
            ef = parse_proto(ev)
            if get_field(ef, 30) is not None:  # DocumentCreated
                f30 = parse_proto(get_field(ef, 30))
                f2 = get_field(f30, 2)
                if f2 is not None:
                    t_raw = get_field(parse_proto(f2), 1)
                    if t_raw is not None:
                        title = t_raw.decode("utf-8")
            elif get_field(ef, 2) is not None:  # TemplateCreated
                f2 = parse_proto(get_field(ef, 2))
                tpl_id = get_field(f2, 2).decode("utf-8")
                f7 = get_field(f2, 7)
                ls = struct.unpack("<d", f7)[0] if f7 else 32.083335876464844
                w, h = 1091.35, 1543.46
                f8 = get_field(f2, 8)
                if f8 is not None:
                    dims = parse_proto(f8)
                    w = struct.unpack("<f", get_field(dims, 1))[0]
                    h = struct.unpack("<f", get_field(dims, 2))[0]
                y_start = 60.5
                f18 = get_field(f2, 18)
                if f18 is not None:
                    f18_1 = get_field(parse_proto(f18), 1)
                    if f18_1 is not None:
                        f18_1_1 = get_field(parse_proto(f18_1), 1)
                        if f18_1_1 is not None:
                            y_raw = get_field(parse_proto(f18_1_1), 2)
                            if y_raw is not None:
                                y_start = struct.unpack("<f", y_raw)[0]
                tname = get_field(f2, 9).decode("utf-8") if get_field(f2, 9) else ""
                templates[tpl_id] = {
                    "width": w,
                    "height": h,
                    "line_spacing": ls,
                    "y_start": y_start,
                    "name": tname,
                }
            elif get_field(ef, 54) is not None:  # PageCreated
                f54 = parse_proto(get_field(ef, 54))
                pid = get_field(f54, 2).decode("utf-8")
                tpl_id = get_field(parse_proto(get_field(f54, 3)), 1).decode("utf-8") if get_field(f54, 3) else None
                sort_key = get_field(parse_proto(get_field(f54, 4)), 1).decode("utf-8") if get_field(f54, 4) else ""
                pages_meta[pid] = {"tpl_id": tpl_id, "sort_key": sort_key}
            elif get_field(ef, 56) is not None:  # PageDeleted
                f56 = parse_proto(get_field(ef, 56))
                pid = get_field(f56, 2).decode("utf-8")
                f3 = get_field(f56, 3)
                if f3 is not None and get_field(parse_proto(f3), 1, 0) == 1:
                    deleted_pages.add(pid)

        ordered = sorted(
            [(pid, meta) for pid, meta in pages_meta.items() if include_deleted_pages or pid not in deleted_pages],
            key=lambda x: x[1]["sort_key"],
        )

        pages: List[GoodnotesPage] = []
        for idx, (pid, meta) in enumerate(ordered):
            note_uuid = increment_uuid(pid, 1)
            note_path = f"notes/{note_uuid}"
            tpl = templates.get(meta["tpl_id"], {
                "width": 1091.35,
                "height": 1543.46,
                "line_spacing": 32.083335876464844,
                "y_start": 60.5,
                "name": "",
            })

            strokes: List[InkStroke] = []
            if note_path in names:
                raw_note = zf.read(note_path)
                if raw_note:
                    note_msgs = decode_delimited(raw_note)
                    for i in range(0, len(note_msgs), 2):
                        if i + 1 >= len(note_msgs):
                            break
                        body_fields = parse_proto(note_msgs[i + 1])
                        elem_raw = get_field(body_fields, 7)
                        if elem_raw is None:
                            continue
                        ef = parse_proto(elem_raw)
                        if get_field(ef, 14, 0):
                            continue
                        uid = get_field(ef, 1).decode("utf-8")
                        blob = get_field(ef, 2)
                        if not blob:
                            continue
                        geom = StrokeGeometry.from_tpl_bytes(bv41_decompress(blob))
                        if not geom.ops:
                            continue
                        color_raw = get_field(ef, 4)
                        color = ColorRGBA.from_proto(color_raw) if color_raw else ColorRGBA()
                        z_index = 0
                        f7 = get_field(ef, 7)
                        if f7 is not None:
                            f7_1 = get_field(parse_proto(f7), 1)
                            if f7_1 is not None:
                                z_index = int(get_field(parse_proto(f7_1), 1, 0))
                        strokes.append(InkStroke(uid=uid, geometry=geom, color=color, z_index=z_index, deleted=False))

            pages.append(
                GoodnotesPage(
                    page_idx=idx,
                    page_uuid=pid,
                    note_uuid=note_uuid,
                    sort_key=meta["sort_key"],
                    width=tpl["width"],
                    height=tpl["height"],
                    line_spacing=tpl["line_spacing"],
                    y_start=tpl["y_start"],
                    template_name=tpl["name"],
                    strokes=strokes,
                )
            )
        return title, pages


def read_goodnotes(path: str, include_deleted: bool = False) -> GoodnotesDocument:
    """Parse a single-page Goodnotes 6 .goodnotes archive."""
    with zipfile.ZipFile(path, "r") as zf:
        # 1. Parse index.notes.pb
        notes_index = decode_delimited(zf.read("index.notes.pb"))
        note_fields = parse_proto(notes_index[0])
        note_uuid = get_field(note_fields, 1).decode("utf-8")
        note_path = get_field(note_fields, 2).decode("utf-8")

        # 2. Parse index.attachments.pb
        att_index = decode_delimited(zf.read("index.attachments.pb"))
        att_fields = parse_proto(att_index[0])
        att_uuid = get_field(att_fields, 1).decode("utf-8")
        att_path = get_field(att_fields, 2).decode("utf-8")
        template_pdf = zf.read(att_path)

        # 3. Parse index.events.pb for metadata (title, page dimensions, UUIDs)
        events = decode_delimited(zf.read("index.events.pb"))
        title = "Untitled"
        page_w, page_h = 1091.35, 1543.46
        doc_uuid = None
        page_uuid = None
        template_uuid = None
        template_name = "238EE861-EE9A-51BD-B010-832CD3C50D2C_a4_1_2 - White"

        for ev in events:
            ef = parse_proto(ev)
            if get_field(ef, 30) is not None:  # Document creation event
                f30 = parse_proto(get_field(ef, 30))
                doc_uuid = get_field(f30, 1).decode("utf-8")
                f2 = get_field(f30, 2)
                if f2 is not None:
                    t_raw = get_field(parse_proto(f2), 1)
                    if t_raw is not None:
                        title = t_raw.decode("utf-8")
            elif get_field(ef, 2) is not None:  # Template definition event
                f2 = parse_proto(get_field(ef, 2))
                template_uuid = get_field(f2, 2).decode("utf-8")
                f8 = get_field(f2, 8)
                if f8 is not None:
                    dims = parse_proto(f8)
                    page_w = struct.unpack("<f", get_field(dims, 1))[0]
                    page_h = struct.unpack("<f", get_field(dims, 2))[0]
                f9 = get_field(f2, 9)
                if f9 is not None:
                    template_name = f9.decode("utf-8")
            elif get_field(ef, 54) is not None:  # Page creation event
                f54 = parse_proto(get_field(ef, 54))
                page_uuid = get_field(f54, 2).decode("utf-8")

        # 4. Parse notes/<NOTE_UUID> stroke pairs
        note_msgs = decode_delimited(zf.read(note_path))
        strokes: List[InkStroke] = []
        for i in range(0, len(note_msgs), 2):
            body_fields = parse_proto(note_msgs[i + 1])
            elem_raw = get_field(body_fields, 7)
            if elem_raw is None:
                continue
            ef = parse_proto(elem_raw)
            uid = get_field(ef, 1).decode("utf-8")
            deleted = bool(get_field(ef, 14, 0))
            if deleted and not include_deleted:
                continue
            blob = get_field(ef, 2)
            geom = StrokeGeometry.from_tpl_bytes(bv41_decompress(blob))
            color_raw = get_field(ef, 4)
            color = ColorRGBA.from_proto(color_raw) if color_raw else ColorRGBA()
            z_index = 0
            f7 = get_field(ef, 7)
            if f7 is not None:
                f7_1 = get_field(parse_proto(f7), 1)
                if f7_1 is not None:
                    z_index = int(get_field(parse_proto(f7_1), 1, 0))
            strokes.append(InkStroke(uid=uid, geometry=geom, color=color, z_index=z_index, deleted=deleted))

        thumb = zf.read("thumbnail.jpg") if "thumbnail.jpg" in zf.namelist() else None

    return GoodnotesDocument(
        title=title,
        page_width=page_w,
        page_height=page_h,
        strokes=strokes,
        template_pdf=template_pdf,
        template_name=template_name,
        base_thumbnail_jpg=thumb,
        doc_uuid=doc_uuid,
        page_uuid=page_uuid,
        note_uuid=note_uuid,
        attachment_uuid=att_uuid,
        template_uuid=template_uuid,
    )


def render_thumbnail(
    strokes: List[InkStroke],
    page_width: float,
    page_height: float,
    base_thumbnail_jpg: Optional[bytes] = None,
    thumb_size: Tuple[int, int] = (353, 499),
) -> bytes:
    """Render strokes onto a base page thumbnail JPEG (uses Pillow if installed)."""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        if base_thumbnail_jpg:
            return base_thumbnail_jpg
        raise

    if base_thumbnail_jpg:
        base_img = Image.open(io.BytesIO(base_thumbnail_jpg)).convert("RGB")
        tw, th = base_img.size
    else:
        tw, th = thumb_size
        base_img = Image.new("RGB", (tw, th), (255, 255, 255))

    # Supersample 2x for crisp anti-aliased strokes
    ss = 2
    img = base_img.resize((tw * ss, th * ss), Image.Resampling.BICUBIC)
    draw = ImageDraw.Draw(img)
    sx = (tw * ss) / page_width
    sy = (th * ss) / page_height

    for st in sorted(strokes, key=lambda s: s.z_index):
        if st.deleted:
            continue
        rgb = (
            int(round(st.color.r * 255)),
            int(round(st.color.g * 255)),
            int(round(st.color.b * 255)),
        )
        line_w = max(1, int(round(st.geometry.width * sx * 1.15)))
        for poly in st.geometry.sample_polyline(steps_per_quad=12):
            pts = [(x * sx, y * sy) for (x, y) in poly]
            if len(pts) >= 2:
                draw.line(pts, fill=rgb, width=line_w, joint="curve")
                # Round caps
                r = line_w / 2.0
                for px, py in (pts[0], pts[-1]):
                    draw.ellipse((px - r, py - r, px + r, py + r), fill=rgb)

    final_img = img.resize((tw, th), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    final_img.save(buf, format="JPEG", quality=85)
    return buf.getvalue()


def _build_notes_stream(strokes: List[InkStroke], device_id: int, base_seq: int = 1313417) -> bytes:
    messages: List[bytes] = []
    for idx, st in enumerate(strokes):
        stroke_uid = st.uid
        clock_bytes = encode_lamport_clock(counter=2)
        z_clock_bytes = encode_lamport_clock(counter=st.z_index)
        compressed_tpl = bv41_compress(st.geometry.to_tpl_bytes())

        # Even message: CRDT Element Metadata
        meta_msg = (
            pb_string(1, stroke_uid)
            + pb_submsg(2, clock_bytes)
            + (pb_varint(3, 1) if st.deleted else b"")
            + pb_varint(8, device_id, omit_zero=False)
            + pb_varint(9, base_seq + idx, omit_zero=False)
            + pb_varint(14, 5381, omit_zero=False)
            + pb_varint(16, 24, omit_zero=False)
        )

        # Odd message: InkStroke Element Payload
        elem_msg = (
            pb_string(1, stroke_uid)
            + pb_bytes(2, compressed_tpl)
            + pb_submsg(4, st.color.to_proto())
            + pb_bytes(6, b"")
            + pb_submsg(7, pb_submsg(1, z_clock_bytes))
            + pb_bytes(9, b"")
            + (pb_varint(14, 1) if st.deleted else b"")
            + pb_submsg(15, clock_bytes)
            + pb_bytes(20, b"")
            + pb_varint(21, 24, omit_zero=False)
        )
        wrapper_msg = pb_submsg(7, elem_msg)

        messages.append(meta_msg)
        messages.append(wrapper_msg)

    return encode_delimited(messages)


def _build_events_stream(
    doc_uuid: str,
    att_uuid: str,
    template_uuid: str,
    page_uuid: str,
    note_uuid: str,
    title: str,
    pdf_size: int,
    page_width: float,
    page_height: float,
    template_name: str,
    device_id: int,
) -> bytes:
    now_ms = time.time() * 1000.0
    hlc = int(now_ms)
    folder_uuid = new_uuid()
    default_tpl_uuid = new_uuid()
    updater_uuid = new_uuid()

    events: List[bytes] = []

    # Event #0 (field 30): Document Creation
    ev0_body = (
        pb_string(1, doc_uuid)
        + pb_submsg(2, encode_lww_string(title, 1))
        + pb_submsg(3, encode_lww_string(folder_uuid, 1))
        + pb_submsg(6, encode_lww_string("P", 1))
        + pb_submsg(7, encode_lww_string(default_tpl_uuid, 1))
        + pb_string(9, "auto")
        + pb_fixed64_double(10, now_ms, omit_zero=False)
        + pb_string(11, new_uuid())
        + pb_varint(13, device_id, omit_zero=False)
        + pb_varint(14, hlc, omit_zero=False)
        + pb_bytes(17, b"")
        + pb_bytes(18, b"")
        + pb_submsg(19, pb_submsg(2, encode_lamport_clock(1)))
        + pb_varint(20, 24, omit_zero=False)
    )
    events.append(pb_string(1, doc_uuid) + pb_submsg(30, ev0_body))

    # Event #1 (field 6): Attachment Registration (PDF template)
    ev1_body = (
        pb_string(1, att_uuid)
        + pb_string(2, att_uuid)
        + pb_varint(5, pdf_size, omit_zero=False)
        + pb_string(6, doc_uuid)
        + pb_fixed64_double(10, now_ms + 3.0, omit_zero=False)
        + pb_string(11, new_uuid())
        + pb_submsg(12, pb_varint(1, 1) + pb_varint(2, 1))
        + pb_varint(14, device_id, omit_zero=False)
        + pb_varint(15, hlc + 3, omit_zero=False)
        + pb_varint(16, 24, omit_zero=False)
    )
    events.append(pb_string(1, att_uuid) + pb_submsg(6, ev1_body))

    # Event #2 (field 2): Page Template Definition
    line_spacing = 32.083333333333336
    dims_msg = pb_fixed32_float(1, page_width, omit_zero=False) + pb_fixed32_float(2, page_height, omit_zero=False)
    margin_tl = pb_fixed32_float(1, 44.0, omit_zero=False) + pb_fixed32_float(2, 60.5, omit_zero=False)
    margin_br = pb_fixed32_float(1, page_width - 88.0, omit_zero=False) + pb_fixed32_float(2, page_height - 120.99, omit_zero=False)
    layout_msg = (
        pb_submsg(1, pb_submsg(1, margin_tl) + pb_submsg(2, margin_br))
        + pb_fixed32_float(2, 31.166666, omit_zero=False)
        + pb_fixed32_float(3, 0.9166667, omit_zero=False)
        + pb_varint(5, 1)
    )
    ev2_body = (
        pb_string(1, doc_uuid)
        + pb_string(2, template_uuid)
        + pb_string(4, att_uuid)
        + pb_varint(5, 1)
        + pb_varint(6, 1)
        + pb_fixed64_double(7, line_spacing, omit_zero=False)
        + pb_submsg(8, dims_msg)
        + pb_string(9, template_name)
        + pb_fixed64_double(10, now_ms + 4.0, omit_zero=False)
        + pb_string(11, new_uuid())
        + pb_submsg(12, encode_lww_double(line_spacing, 1))
        + pb_submsg(13, encode_lww_varint(1, 1))
        + pb_varint(15, device_id, omit_zero=False)
        + pb_varint(16, hlc + 4, omit_zero=False)
        + pb_submsg(17, encode_lww_varint(1, 1))
        + pb_submsg(18, layout_msg)
        + pb_submsg(19, pb_submsg(2, encode_lamport_clock(1)))
        + pb_varint(21, 24, omit_zero=False)
    )
    events.append(pb_string(1, template_uuid) + pb_submsg(2, ev2_body))

    # Event #3 (field 54): Page Creation
    c_gray = ColorRGBA(221 / 255.0, 221 / 255.0, 221 / 255.0, 1.0).to_proto()
    c_white = ColorRGBA(1.0, 1.0, 1.0, 1.0).to_proto()
    bg_style = pb_submsg(1, pb_submsg(2, pb_submsg(1, c_gray) + pb_submsg(2, c_white))) + pb_submsg(2, encode_lamport_clock(1))
    ev3_body = (
        pb_string(1, doc_uuid)
        + pb_string(2, page_uuid)
        + pb_submsg(3, encode_lww_string(template_uuid, 1))
        + pb_submsg(4, encode_lww_string("4VNPN2", 1))
        + pb_fixed64_double(10, now_ms + 6.0, omit_zero=False)
        + pb_string(11, new_uuid())
        + pb_varint(13, device_id, omit_zero=False)
        + pb_varint(14, hlc + 6, omit_zero=False)
        + pb_varint(15, 24, omit_zero=False)
        + pb_submsg(17, bg_style)
    )
    events.append(pb_string(1, page_uuid) + pb_submsg(54, ev3_body))

    # Event #4 (field 10): Paging View Current Page State
    ev4_body = (
        pb_string(1, doc_uuid)
        + pb_string(2, page_uuid)
        + pb_string(3, f"PagingViewServiceUpdater:{updater_uuid}")
        + pb_fixed64_double(10, now_ms + 13.0, omit_zero=False)
        + pb_string(11, new_uuid())
        + pb_varint(13, device_id, omit_zero=False)
        + pb_varint(14, hlc + 13, omit_zero=False)
        + pb_varint(15, 24, omit_zero=False)
    )
    events.append(pb_string(1, doc_uuid) + pb_submsg(10, ev4_body))

    # Event #5 (field 102): Note Ink Layer Registration
    ev5_body = (
        pb_string(1, note_uuid)
        + pb_fixed64_double(10, now_ms + 19.0, omit_zero=False)
        + pb_string(11, new_uuid())
        + pb_varint(13, device_id, omit_zero=False)
        + pb_varint(14, hlc + 19, omit_zero=False)
        + pb_varint(15, 24, omit_zero=False)
        + pb_string(16, doc_uuid)
    )
    events.append(pb_string(1, note_uuid) + pb_submsg(102, ev5_body))

    # Event #6 (field 105): Search Index Registration
    ev6_body = (
        pb_string(2, doc_uuid)
        + pb_string(3, att_uuid)
        + pb_fixed64_double(10, now_ms + 22.0, omit_zero=False)
        + pb_string(11, new_uuid())
        + pb_varint(13, device_id, omit_zero=False)
        + pb_varint(14, hlc + 22, omit_zero=False)
        + pb_varint(15, 24, omit_zero=False)
    )
    events.append(pb_string(1, att_uuid) + pb_submsg(105, ev6_body))

    return encode_delimited(events)


def write_goodnotes_multipage(
    title: str,
    pages_strokes: List[List[InkStroke]],
    template_pdf: bytes,
    page_width: float = 1091.35,
    page_height: float = 1543.46,
    template_name: str = "238EE861-EE9A-51BD-B010-832CD3C50D2C_a4_1_2 - White",
    base_thumbnail_jpg: Optional[bytes] = None,
    out_path: Optional[str] = None,
) -> bytes:
    """
    Serialize an arbitrary number of pages into a valid, Goodnotes-6-importable
    multi-page .goodnotes ZIP archive. Returns the raw archive bytes (and optionally
    writes them to out_path).
    """
    if not pages_strokes:
        pages_strokes = [[]]

    doc_uuid = new_uuid()
    att_uuid = new_uuid()
    template_uuid = new_uuid()
    device_id = random.getrandbits(62)

    now_ms = time.time() * 1000.0
    hlc = int(now_ms)
    folder_uuid = new_uuid()
    default_tpl_uuid = new_uuid()
    updater_uuid = new_uuid()

    # Generate consistent PAGE_UUID & NOTE_UUID = PAGE_UUID + 1 for every page
    page_entries = []
    for p_idx, strokes in enumerate(pages_strokes):
        page_uuid = new_uuid()
        note_uuid = increment_uuid(page_uuid, 1)
        sort_key = f"a{p_idx:05d}"
        prepared = [
            InkStroke(
                uid=st.uid or new_uuid(),
                geometry=st.geometry,
                color=st.color,
                z_index=z,
                deleted=st.deleted,
            )
            for z, st in enumerate(strokes)
        ]
        page_entries.append((p_idx, page_uuid, note_uuid, sort_key, prepared))

    # Build events stream
    events: List[bytes] = []

    # Event #0 (field 30): Document Creation
    ev0_body = (
        pb_string(1, doc_uuid)
        + pb_submsg(2, encode_lww_string(title, 1))
        + pb_submsg(3, encode_lww_string(folder_uuid, 1))
        + pb_submsg(6, encode_lww_string("P", 1))
        + pb_submsg(7, encode_lww_string(default_tpl_uuid, 1))
        + pb_string(9, "auto")
        + pb_fixed64_double(10, now_ms, omit_zero=False)
        + pb_string(11, new_uuid())
        + pb_varint(13, device_id, omit_zero=False)
        + pb_varint(14, hlc, omit_zero=False)
        + pb_bytes(17, b"")
        + pb_bytes(18, b"")
        + pb_submsg(19, pb_submsg(2, encode_lamport_clock(1)))
        + pb_varint(20, 24, omit_zero=False)
    )
    events.append(pb_string(1, doc_uuid) + pb_submsg(30, ev0_body))

    # Event #1 (field 6): Attachment Registration (shared A4 PDF template)
    ev1_body = (
        pb_string(1, att_uuid)
        + pb_string(2, att_uuid)
        + pb_varint(5, len(template_pdf), omit_zero=False)
        + pb_string(6, doc_uuid)
        + pb_fixed64_double(10, now_ms + 3.0, omit_zero=False)
        + pb_string(11, new_uuid())
        + pb_submsg(12, pb_varint(1, 1) + pb_varint(2, 1))
        + pb_varint(14, device_id, omit_zero=False)
        + pb_varint(15, hlc + 3, omit_zero=False)
        + pb_varint(16, 24, omit_zero=False)
    )
    events.append(pb_string(1, att_uuid) + pb_submsg(6, ev1_body))

    # Event #2 (field 2): Page Template Definition (shared across all pages)
    line_spacing = 32.083333333333336
    dims_msg = pb_fixed32_float(1, page_width, omit_zero=False) + pb_fixed32_float(2, page_height, omit_zero=False)
    margin_tl = pb_fixed32_float(1, 44.0, omit_zero=False) + pb_fixed32_float(2, 60.5, omit_zero=False)
    margin_br = pb_fixed32_float(1, page_width - 88.0, omit_zero=False) + pb_fixed32_float(2, page_height - 120.99, omit_zero=False)
    layout_msg = (
        pb_submsg(1, pb_submsg(1, margin_tl) + pb_submsg(2, margin_br))
        + pb_fixed32_float(2, 31.166666, omit_zero=False)
        + pb_fixed32_float(3, 0.9166667, omit_zero=False)
        + pb_varint(5, 1)
    )
    ev2_body = (
        pb_string(1, doc_uuid)
        + pb_string(2, template_uuid)
        + pb_string(4, att_uuid)
        + pb_varint(5, 1)
        + pb_varint(6, 1)
        + pb_fixed64_double(7, line_spacing, omit_zero=False)
        + pb_submsg(8, dims_msg)
        + pb_string(9, template_name)
        + pb_fixed64_double(10, now_ms + 4.0, omit_zero=False)
        + pb_string(11, new_uuid())
        + pb_submsg(12, encode_lww_double(line_spacing, 1))
        + pb_submsg(13, encode_lww_varint(1, 1))
        + pb_varint(15, device_id, omit_zero=False)
        + pb_varint(16, hlc + 4, omit_zero=False)
        + pb_submsg(17, encode_lww_varint(1, 1))
        + pb_submsg(18, layout_msg)
        + pb_submsg(19, pb_submsg(2, encode_lamport_clock(1)))
        + pb_varint(21, 24, omit_zero=False)
    )
    events.append(pb_string(1, template_uuid) + pb_submsg(2, ev2_body))

    # Per-page PageCreated (field 54) events
    c_gray = ColorRGBA(221 / 255.0, 221 / 255.0, 221 / 255.0, 1.0).to_proto()
    c_white = ColorRGBA(1.0, 1.0, 1.0, 1.0).to_proto()
    tick = 6
    for p_idx, page_uuid, note_uuid, sort_key, _prepared in page_entries:
        bg_style = pb_submsg(1, pb_submsg(2, pb_submsg(1, c_gray) + pb_submsg(2, c_white))) + pb_submsg(2, encode_lamport_clock(1))
        ev_page = (
            pb_string(1, doc_uuid)
            + pb_string(2, page_uuid)
            + pb_submsg(3, encode_lww_string(template_uuid, 1))
            + pb_submsg(4, encode_lww_string(sort_key, 1))
            + pb_fixed64_double(10, now_ms + tick, omit_zero=False)
            + pb_string(11, new_uuid())
            + pb_varint(13, device_id, omit_zero=False)
            + pb_varint(14, hlc + tick, omit_zero=False)
            + pb_varint(15, 24, omit_zero=False)
            + pb_submsg(17, bg_style)
        )
        events.append(pb_string(1, page_uuid) + pb_submsg(54, ev_page))
        tick += 2

    # PagingViewState (field 10) pointing to first page
    first_page_uuid = page_entries[0][1]
    ev_paging = (
        pb_string(1, doc_uuid)
        + pb_string(2, first_page_uuid)
        + pb_string(3, f"PagingViewServiceUpdater:{updater_uuid}")
        + pb_fixed64_double(10, now_ms + tick, omit_zero=False)
        + pb_string(11, new_uuid())
        + pb_varint(13, device_id, omit_zero=False)
        + pb_varint(14, hlc + tick, omit_zero=False)
        + pb_varint(15, 24, omit_zero=False)
    )
    events.append(pb_string(1, doc_uuid) + pb_submsg(10, ev_paging))
    tick += 2

    # Per-page NoteLayerRegistered (field 102) events
    for p_idx, page_uuid, note_uuid, _sort_key, _prepared in page_entries:
        ev_note = (
            pb_string(1, note_uuid)
            + pb_fixed64_double(10, now_ms + tick, omit_zero=False)
            + pb_string(11, new_uuid())
            + pb_varint(13, device_id, omit_zero=False)
            + pb_varint(14, hlc + tick, omit_zero=False)
            + pb_varint(15, 24, omit_zero=False)
            + pb_string(16, doc_uuid)
        )
        events.append(pb_string(1, note_uuid) + pb_submsg(102, ev_note))
        tick += 2

    # Search Index Registration (field 105)
    ev_search = (
        pb_string(2, doc_uuid)
        + pb_string(3, att_uuid)
        + pb_fixed64_double(10, now_ms + tick, omit_zero=False)
        + pb_string(11, new_uuid())
        + pb_varint(13, device_id, omit_zero=False)
        + pb_varint(14, hlc + tick, omit_zero=False)
        + pb_varint(15, 24, omit_zero=False)
    )
    events.append(pb_string(1, att_uuid) + pb_submsg(105, ev_search))

    # Build index files & per-page notes streams
    schema_pb = pb_varint(1, 24, omit_zero=False)
    document_info_pb = b""
    index_attachments_pb = encode_delimited([
        pb_string(1, att_uuid) + pb_string(2, f"attachments/{att_uuid}")
    ])
    index_search_pb = encode_delimited([
        pb_string(1, att_uuid) + pb_string(2, f"search/{att_uuid}") + pb_varint(3, 1)
    ])
    search_blob = encode_delimited([
        pb_varint(2, 1) + pb_bytes(3, b"")
    ])
    index_notes_pb = encode_delimited([
        pb_string(1, note_uuid) + pb_string(2, f"notes/{note_uuid}")
        for (_p_idx, _page_uuid, note_uuid, _sk, _prep) in page_entries
    ])
    index_events_pb = encode_delimited(events)

    # Render thumbnail of Page 0
    thumbnail_jpg = render_thumbnail(
        page_entries[0][4],
        page_width=page_width,
        page_height=page_height,
        base_thumbnail_jpg=base_thumbnail_jpg,
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("document.info.pb", document_info_pb)
        zf.writestr("index.search.pb", index_search_pb)
        zf.writestr("index.notes.pb", index_notes_pb)
        zf.writestr(f"search/{att_uuid}", search_blob)
        seq = 1313417
        for (_p_idx, _page_uuid, note_uuid, _sk, prepared) in page_entries:
            notes_blob = _build_notes_stream(prepared, device_id=device_id, base_seq=seq)
            seq += len(prepared) + 1
            zf.writestr(f"notes/{note_uuid}", notes_blob)
        zf.writestr("index.events.pb", index_events_pb)
        zf.writestr("thumbnail.jpg", thumbnail_jpg)
        zf.writestr("index.attachments.pb", index_attachments_pb)
        zf.writestr(f"attachments/{att_uuid}", template_pdf)
        zf.writestr("schema.pb", schema_pb)

    raw_bytes = buf.getvalue()
    if out_path:
        with open(out_path, "wb") as f:
            f.write(raw_bytes)
    return raw_bytes


def write_goodnotes(doc: GoodnotesDocument, out_path: str) -> Dict[str, str]:
    """
    Serialize a GoodnotesDocument into a valid, Goodnotes-6-importable .goodnotes archive.
    Generates fresh consistent UUIDs (enforcing NOTE_UUID == PAGE_UUID + 1) unless provided.
    """
    doc_uuid = doc.doc_uuid or new_uuid()
    att_uuid = doc.attachment_uuid or new_uuid()
    template_uuid = doc.template_uuid or new_uuid()
    page_uuid = doc.page_uuid or new_uuid()
    note_uuid = doc.note_uuid or increment_uuid(page_uuid, 1)
    device_id = random.getrandbits(62)

    # Ensure unique stroke UUIDs & sequential z-order
    prepared_strokes: List[InkStroke] = []
    for z, st in enumerate(doc.strokes):
        prepared_strokes.append(
            InkStroke(
                uid=st.uid or new_uuid(),
                geometry=st.geometry,
                color=st.color,
                z_index=z,
                deleted=st.deleted,
            )
        )

    schema_pb = pb_varint(1, 24, omit_zero=False)  # Raw (non-delimited) protobuf
    document_info_pb = b""

    index_attachments_pb = encode_delimited([
        pb_string(1, att_uuid) + pb_string(2, f"attachments/{att_uuid}")
    ])
    index_search_pb = encode_delimited([
        pb_string(1, att_uuid) + pb_string(2, f"search/{att_uuid}") + pb_varint(3, 1)
    ])
    search_blob = encode_delimited([
        pb_varint(2, 1) + pb_bytes(3, b"")
    ])
    index_notes_pb = encode_delimited([
        pb_string(1, note_uuid) + pb_string(2, f"notes/{note_uuid}")
    ])
    notes_blob = _build_notes_stream(prepared_strokes, device_id=device_id)
    index_events_pb = _build_events_stream(
        doc_uuid=doc_uuid,
        att_uuid=att_uuid,
        template_uuid=template_uuid,
        page_uuid=page_uuid,
        note_uuid=note_uuid,
        title=doc.title,
        pdf_size=len(doc.template_pdf),
        page_width=doc.page_width,
        page_height=doc.page_height,
        template_name=doc.template_name,
        device_id=device_id,
    )
    thumbnail_jpg = render_thumbnail(
        prepared_strokes,
        page_width=doc.page_width,
        page_height=doc.page_height,
        base_thumbnail_jpg=doc.base_thumbnail_jpg,
    )

    entries = [
        ("document.info.pb", document_info_pb),
        ("index.search.pb", index_search_pb),
        ("index.notes.pb", index_notes_pb),
        (f"search/{att_uuid}", search_blob),
        (f"notes/{note_uuid}", notes_blob),
        ("index.events.pb", index_events_pb),
        ("thumbnail.jpg", thumbnail_jpg),
        ("index.attachments.pb", index_attachments_pb),
        (f"attachments/{att_uuid}", doc.template_pdf),
        ("schema.pb", schema_pb),
    ]

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)

    return {
        "doc_uuid": doc_uuid,
        "attachment_uuid": att_uuid,
        "template_uuid": template_uuid,
        "page_uuid": page_uuid,
        "note_uuid": note_uuid,
    }
