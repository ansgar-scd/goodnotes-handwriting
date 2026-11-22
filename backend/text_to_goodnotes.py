"""
German Text -> Goodnotes 6 (.goodnotes) Handwriting Layout Engine.

Features:
- Greedy longest-first ligature matching + non-repeating random variant selection
- Realistic handwriting micro-variance (scale +/-4%, rotation +/-1.5 deg,
  baseline jitter +/-1.5 px, smooth per-line Y-drift, tight/negative kerning)
- Clean word wrapping (never breaks words mid-word unless wider than the page)
- Unlimited automatic multi-page pagination
"""

from __future__ import annotations

import json
import math
import os
import random
from typing import Dict, List, Optional, Tuple

from goodnotes_format import (
    ColorRGBA,
    InkStroke,
    StrokeGeometry,
    new_uuid,
    write_goodnotes_multipage,
)

# A4 portrait canvas metrics matching Goodnotes 6 template
PAGE_WIDTH = 1091.35
PAGE_HEIGHT = 1543.46
LINE_Y_START = 60.5
LINE_SPACING = 32.083335876464844
FIRST_LINE_INDEX = 2          # Line 3 (y ~ 124.67) leaves comfortable top headroom
MAX_BASELINE_Y = 1478.0       # ~43 lines per A4 page

MARGIN_LEFT = 58.0
MARGIN_RIGHT = 58.0

DESCENDER_CHARS = set("gjpqyßJ")
PUNCTUATION_CHARS = set(".,!?:;-–()\"'„“/[]")
CHAR_FALLBACKS = {
    "’": "'",
    "‘": "'",
    "”": "“",
    "«": "„",
    "»": "“",
    "—": "–",
    "\u00a0": " ",  # non-breaking space
}


class HandwritingEngine:
    def __init__(self, glyph_bank: dict, template_pdf: bytes, base_thumbnail_jpg: Optional[bytes] = None):
        self.glyphs: Dict[str, List[dict]] = glyph_bank.get("glyphs", {})
        self.template_pdf = template_pdf
        self.base_thumbnail_jpg = base_thumbnail_jpg

        # Pre-sort multi-char ligatures longest-first for greedy matching
        self.ligatures: List[str] = sorted(
            [k for k in self.glyphs.keys() if len(k) > 1 and self.glyphs[k]],
            key=len,
            reverse=True,
        )
        # Pre-index ligatures by first character for O(1) lookup
        self.ligatures_by_first: Dict[str, List[str]] = {}
        for lig in self.ligatures:
            self.ligatures_by_first.setdefault(lig[0], []).append(lig)

    @classmethod
    def from_files(cls, bank_path: str, template_pdf_path: str, thumb_path: Optional[str] = None) -> "HandwritingEngine":
        with open(bank_path, "r", encoding="utf-8") as f:
            bank = json.load(f)
        with open(template_pdf_path, "rb") as f:
            pdf = f.read()
        thumb = None
        if thumb_path and os.path.exists(thumb_path):
            with open(thumb_path, "rb") as f:
                thumb = f.read()
        return cls(bank, pdf, thumb)

    def available_keys(self) -> List[str]:
        return sorted(k for k, v in self.glyphs.items() if v)

    def tokenize_word(self, word: str, missing_set: set) -> List[str]:
        """Greedy longest-first ligature tokenization for a single word."""
        tokens: List[str] = []
        i = 0
        n = len(word)
        while i < n:
            ch = word[i]
            matched = None
            candidates = self.ligatures_by_first.get(ch)
            if candidates:
                for lig in candidates:
                    if word.startswith(lig, i):
                        matched = lig
                        break
            if matched is not None:
                tokens.append(matched)
                i += len(matched)
                continue

            if ch in self.glyphs and self.glyphs[ch]:
                tokens.append(ch)
            else:
                fb = CHAR_FALLBACKS.get(ch)
                if fb and fb in self.glyphs and self.glyphs[fb]:
                    tokens.append(fb)
                elif ch.strip():
                    missing_set.add(ch)
            i += 1
        return tokens

    def _pick_variant(self, key: str, last_idx: Dict[str, int], rng: random.Random) -> dict:
        variants = self.glyphs[key]
        if len(variants) == 1:
            return variants[0]
        prev = last_idx.get(key, -1)
        idx = rng.randrange(len(variants) - 1)
        if idx >= prev and prev >= 0:
            idx += 1
        last_idx[key] = idx
        return variants[idx]

    @staticmethod
    def _effective_baseline_offset(key: str, variant: dict) -> float:
        """
        Return the baseline offset relative to glyph top (min_y = 0).
        Guards against descender variants (g, p, q, y, j) whose auto-snapped
        baseline landed on the ruled line below the glyph.
        """
        bl = float(variant["baseline_offset"])
        h = float(variant["height"])
        ls = float(variant.get("line_spacing") or LINE_SPACING)
        if any(c in DESCENDER_CHARS for c in key) and bl > h + 4.0 and (bl - ls) > 4.0:
            return bl - ls
        return bl

    @staticmethod
    def _kerning_after(key: str, next_key: Optional[str], rng: random.Random) -> float:
        """Tight / slightly negative kerning for natural connected German handwriting."""
        if next_key is None:
            return 0.0
        if key in PUNCTUATION_CHARS or next_key in PUNCTUATION_CHARS:
            return rng.uniform(0.2, 1.8)
        # Tight / slightly negative kerning between letter glyphs
        return rng.uniform(-2.2, -0.4)

    @staticmethod
    def _transform_variant(
        variant: dict,
        x_origin: float,
        baseline_y: float,
        baseline_offset: float,
        scale: float,
        angle_deg: float,
    ) -> List[InkStroke]:
        """Transform a normalized glyph variant into world-space InkStrokes."""
        w = float(variant["width"])
        h = float(variant["height"])
        cx_local = w * 0.5
        cy_local = h * 0.5

        rad = math.radians(angle_deg)
        cos_a = math.cos(rad)
        sin_a = math.sin(rad)

        # Anchor: after scaling around (0, 0), baseline_offset * scale sits at baseline_y
        # Rotation happens around the scaled glyph center
        tx = x_origin
        ty = baseline_y - baseline_offset * scale
        rcx = cx_local * scale
        rcy = cy_local * scale

        def xform(x: float, y: float) -> Tuple[float, float]:
            sx = x * scale - rcx
            sy = y * scale - rcy
            rx = sx * cos_a - sy * sin_a + rcx + tx
            ry = sx * sin_a + sy * cos_a + rcy + ty
            return (rx, ry)

        out_strokes: List[InkStroke] = []
        for st in variant["strokes"]:
            moves = [xform(mx, my) for (mx, my) in st["moves"]]
            quads = []
            for (qcx, qcy, qex, qey) in st["quads"]:
                ncx, ncy = xform(qcx, qcy)
                nex, ney = xform(qex, qey)
                quads.append((ncx, ncy, nex, ney))
            c = st.get("color", [0.0, 0.0, 0.0, 1.0])
            geom = StrokeGeometry(
                version=int(st.get("version", 2)),
                width=float(st.get("width", 2.07874)) * (0.95 + 0.05 * scale),
                ops=list(st["ops"]),
                moves=moves,
                quads=quads,
                style=int(st.get("style", 1)),
                pressures=list(st.get("pressures", [])),
            )
            out_strokes.append(
                InkStroke(
                    uid=new_uuid(),
                    geometry=geom,
                    color=ColorRGBA(c[0], c[1], c[2], c[3]),
                    z_index=0,
                    deleted=False,
                )
            )
        return out_strokes

    def generate(
        self,
        text: str,
        title: str = "Handschrift",
        seed: Optional[int] = None,
    ) -> Tuple[bytes, dict]:
        """
        Convert arbitrary-length German text into a multi-page Goodnotes 6 .goodnotes archive.
        Returns (archive_bytes, stats).
        """
        rng = random.Random(seed)
        missing_set: set = set()
        last_variant_idx: Dict[str, int] = {}

        pages_strokes: List[List[InkStroke]] = [[]]
        current_page_idx = 0
        line_idx = FIRST_LINE_INDEX
        max_x = PAGE_WIDTH - MARGIN_RIGHT
        max_line_width = max_x - MARGIN_LEFT

        matched_ligatures = 0
        total_glyphs = 0

        def make_line_drift():
            return (
                rng.uniform(-0.0022, 0.0022),  # gentle slope along X
                rng.uniform(-1.4, 1.4),        # wave amplitude
                rng.uniform(0.0, math.tau),    # wave phase
                rng.uniform(-3.0, 3.0),        # subtle left-margin jitter
            )

        slope, wave_amp, wave_phase, left_jitter = make_line_drift()
        cursor_x = MARGIN_LEFT + left_jitter

        def advance_line():
            nonlocal current_page_idx, line_idx, cursor_x, slope, wave_amp, wave_phase, left_jitter
            line_idx += 1
            next_y = LINE_Y_START + line_idx * LINE_SPACING
            if next_y > MAX_BASELINE_Y:
                pages_strokes.append([])
                current_page_idx += 1
                line_idx = FIRST_LINE_INDEX
            slope, wave_amp, wave_phase, left_jitter = make_line_drift()
            cursor_x = MARGIN_LEFT + left_jitter

        # Normalize line endings
        paragraphs = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")

        for p_i, para in enumerate(paragraphs):
            if p_i > 0:
                advance_line()

            if not para.strip():
                continue

            # Split into words while preserving leading indentation if any
            words = para.split(" ")
            for w_i, raw_word in enumerate(words):
                if not raw_word:
                    # Extra space
                    cursor_x += rng.uniform(16.0, 21.0)
                    continue

                tokens = self.tokenize_word(raw_word, missing_set)
                if not tokens:
                    continue

                # Pre-select variants & micro-variance for this word so we know its exact width
                word_plan = []
                word_width = 0.0
                for t_i, tok in enumerate(tokens):
                    var = self._pick_variant(tok, last_variant_idx, rng)
                    scale = rng.uniform(0.96, 1.04)  # +/-4%
                    angle = rng.uniform(-1.5, 1.5)   # +/-1.5 deg
                    jitter_y = rng.uniform(-1.5, 1.5)
                    next_tok = tokens[t_i + 1] if t_i + 1 < len(tokens) else None
                    kern = self._kerning_after(tok, next_tok, rng)
                    adv = float(var["width"]) * scale + kern
                    word_plan.append((tok, var, scale, angle, jitter_y, adv))
                    word_width += adv
                    if len(tok) > 1:
                        matched_ligatures += 1

                # Word wrap: move to next line if word doesn't fit (unless we're at line start)
                if cursor_x > MARGIN_LEFT + 10.0 and (cursor_x + word_width) > max_x:
                    advance_line()

                # Place each glyph in the word
                for tok, var, scale, angle, jitter_y, adv in word_plan:
                    # Fallback wrap only for abnormally long single words exceeding page width
                    if (cursor_x + float(var["width"]) * scale) > max_x and cursor_x > MARGIN_LEFT + 10.0:
                        advance_line()

                    base_y = LINE_Y_START + line_idx * LINE_SPACING
                    rel_x = cursor_x - MARGIN_LEFT
                    drift_y = slope * rel_x + wave_amp * math.sin(rel_x / 180.0 + wave_phase)
                    bl_offset = self._effective_baseline_offset(tok, var)

                    strokes = self._transform_variant(
                        variant=var,
                        x_origin=cursor_x,
                        baseline_y=base_y + drift_y + jitter_y,
                        baseline_offset=bl_offset,
                        scale=scale,
                        angle_deg=angle,
                    )
                    pages_strokes[current_page_idx].extend(strokes)
                    cursor_x += max(adv, 2.0)
                    total_glyphs += 1

                # Inter-word space
                if w_i < len(words) - 1:
                    cursor_x += rng.uniform(17.5, 23.0)

        archive_bytes = write_goodnotes_multipage(
            title=title,
            pages_strokes=pages_strokes,
            template_pdf=self.template_pdf,
            page_width=PAGE_WIDTH,
            page_height=PAGE_HEIGHT,
            base_thumbnail_jpg=self.base_thumbnail_jpg,
        )

        stats = {
            "pages": len(pages_strokes),
            "total_glyphs": total_glyphs,
            "matched_ligatures": matched_ligatures,
            "total_strokes": sum(len(p) for p in pages_strokes),
            "missing_chars": sorted(missing_set),
            "bytes": len(archive_bytes),
        }
        return archive_bytes, stats
