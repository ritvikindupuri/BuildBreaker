"""Render terminal-style PNGs from saved demo output in examples/."""

import os
import textwrap

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "docs", "assets", "screenshots")
FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 18)
BOLD = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 18)
UI = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 16)
BG, FG, DIM = (13, 17, 23), (201, 209, 217), (110, 118, 129)
COLORS = {
    "PROVEN": (255, 123, 114),
    "CRITICAL": (255, 123, 114),
    "LIKELY": (227, 179, 65),
    "HIGH": (255, 166, 87),
    "MEDIUM": (227, 179, 65),
    "BLOCKED": (63, 185, 80),
    "LOW": (121, 192, 255),
    "NA": DIM,
    "INFO": DIM,
    "ERROR": (210, 150, 255),
    "Verdict: BUILD SURFACE EXPOSED": (255, 123, 114),
    "Verdict: PARTIAL EXPOSURE": (227, 179, 65),
    "Verdict: HARDENED": (63, 185, 80),
}
WRAP = 118
ELIDE = "\0..."


def select(path, ranges):
    lines = open(os.path.join(ROOT, path)).read().splitlines()
    out = []
    for i, (a, b) in enumerate(ranges):
        if i:
            out.append(ELIDE)
        out.extend(lines[a - 1 : b])
    return out


def wrap(lines):
    res = []
    for line in lines:
        if line == ELIDE or len(line) <= WRAP:
            res.append(line)
            continue
        indent = len(line) - len(line.lstrip())
        parts = textwrap.wrap(line.strip(), WRAP - indent - 2)
        res.append(" " * indent + parts[0])
        res.extend(" " * (indent + 2) + p for p in parts[1:])
    return res


def color_for(line):
    s = line.strip()
    for key in (
        "Verdict: BUILD SURFACE EXPOSED",
        "Verdict: PARTIAL EXPOSURE",
        "Verdict: HARDENED",
    ):
        if s.startswith(key):
            return COLORS[key], True
    first = s.split(" ")[0] if s else ""
    if first in COLORS:
        return COLORS[first], True
    if s in ("Targets", "Builder", "Summary", "Findings", "Attack context", "Safety") or s.startswith(
        "BuildBreaker 0.1.0"
    ):
        return (121, 192, 255), True
    if "[PROVEN]" in s:
        return COLORS["PROVEN"], False
    if "[BLOCKED]" in s:
        return COLORS["BLOCKED"], False
    return FG, False


def render(name, title, lines):
    lines = wrap(lines)
    lh, pad, bar = 26, 26, 40
    cw = FONT.getlength("M")
    width = int(max((len(l) for l in lines if l != ELIDE), default=80) * cw + pad * 2)
    width = max(width, 900)
    height = bar + pad * 2 + lh * len(lines)
    img = Image.new("RGB", (width + 40, height + 40), (240, 243, 246))
    d = ImageDraw.Draw(img)
    x0, y0 = 20, 20
    d.rounded_rectangle([x0, y0, x0 + width, y0 + height], 12, fill=BG)
    d.rounded_rectangle([x0, y0, x0 + width, y0 + bar], 12, fill=(33, 38, 45))
    d.rectangle([x0, y0 + bar - 12, x0 + width, y0 + bar], fill=(33, 38, 45))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([x0 + 16 + i * 22, y0 + 14, x0 + 28 + i * 22, y0 + 26], fill=c)
    tw = d.textlength(title, font=UI)
    d.text((x0 + (width - tw) / 2, y0 + 11), title, font=UI, fill=(160, 168, 178))
    y = y0 + bar + pad
    for line in lines:
        if line == ELIDE:
            d.text((x0 + pad, y), "  ...", font=FONT, fill=DIM)
        else:
            col, bold = color_for(line)
            s = line.lstrip()
            lead = len(line) - len(s)
            first, _, rest = s.partition(" ")
            if col != FG and first in COLORS and not s.startswith("Verdict"):
                d.text((x0 + pad + lead * cw, y), first, font=BOLD, fill=col)
                d.text((x0 + pad + (lead + len(first)) * cw, y), " " + rest, font=FONT, fill=FG)
            else:
                d.text((x0 + pad + lead * cw, y), s, font=BOLD if bold else FONT, fill=col)
        y += lh
    img.save(os.path.join(OUT, name))
    print("wrote", name, img.size)


FIGS = [
    (
        "default-summary.png",
        "examples/default-run.txt",
        "examples/default-run.txt",
        [(1, 22)],
    ),
    (
        "default-findings.png",
        "examples/default-run.txt",
        "examples/default-run.txt",
        [(1, 3), (19, 39)],
    ),
    (
        "default-path-blocked.png",
        "examples/default-run.txt",
        "examples/default-run.txt",
        [(24, 24), (48, 55)],
    ),
    (
        "hardened-summary.png",
        "examples/hardened-run.txt",
        "examples/hardened-run.txt",
        [(1, 22)],
    ),
    (
        "hardened-network-blocked.png",
        "examples/hardened-run.txt",
        "examples/hardened-run.txt",
        [(19, 22), (41, 47)],
    ),
]

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for name, title, path, ranges in FIGS:
        render(name, title, select(path, ranges))
