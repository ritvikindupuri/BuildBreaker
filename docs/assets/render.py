"""Render the BuildBreaker logo and architecture diagram (docs/assets/*.png).

Requires cairosvg. Icons: Simple Icons (CC0) for Docker, GitHub, Linux;
custom layer stack for BuildKit; custom cloud for IMDS.
"""

import base64
import os
import re

import cairosvg

HERE = os.path.dirname(os.path.abspath(__file__))
ICONS = os.path.join(HERE, "icons")
BRAND = {"docker": "#2496ED", "github": "#181717", "linux": "#222222"}

GENERIC = {
    "gen": (
        '<circle cx="12" cy="12" r="3.2" fill="none" stroke="#F97316" stroke-width="1.8"/>'
        '<path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1" '
        'stroke="#F97316" stroke-width="1.8" stroke-linecap="round"/>'
        '<circle cx="12" cy="12" r="7" fill="none" stroke="#F97316" stroke-width="1.8"/>'
    ),
    "probe": (
        '<rect x="4" y="3" width="16" height="18" rx="2" fill="none" stroke="#475569" stroke-width="1.6"/>'
        '<path d="M8 8h8M8 12h8M8 16h5" stroke="#F97316" stroke-width="1.8" stroke-linecap="round"/>'
    ),
    "parse": (
        '<circle cx="10" cy="10" r="6.5" fill="none" stroke="#1E3A8A" stroke-width="2"/>'
        '<path d="M15 15l6 6" stroke="#1E3A8A" stroke-width="2.4" stroke-linecap="round"/>'
        '<path d="M7 10h6M10 7v6" stroke="#F97316" stroke-width="1.6" stroke-linecap="round"/>'
    ),
    "findings": (
        '<path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z" fill="none" stroke="#DC2626" '
        'stroke-width="1.8" stroke-linejoin="round"/>'
        '<path d="M9 12h6M12 9v6" stroke="#DC2626" stroke-width="1.8" stroke-linecap="round"/>'
    ),
    "report": (
        '<rect x="4" y="3" width="16" height="18" rx="2" fill="none" stroke="#475569" stroke-width="1.6"/>'
        '<path d="M8 15v2M12 11v6M16 8v9" stroke="#F97316" stroke-width="2" stroke-linecap="round"/>'
    ),
    "tenant": (
        '<circle cx="8" cy="8" r="3" fill="none" stroke="#7C3AED" stroke-width="1.8"/>'
        '<circle cx="16" cy="8" r="3" fill="none" stroke="#7C3AED" stroke-width="1.8"/>'
        '<path d="M3 20c0-3 2.5-5 5-5s5 2 5 5M11 20c0-3 2.5-5 5-5s5 2 5 5" fill="none" '
        'stroke="#7C3AED" stroke-width="1.8" stroke-linecap="round"/>'
    ),
    "fix": (
        '<path d="M4 18 L12 4 L20 18 Z" fill="none" stroke="#16A34A" stroke-width="1.8" stroke-linejoin="round"/>'
        '<path d="M9 18l3-5 3 5" fill="none" stroke="#16A34A" stroke-width="1.8" stroke-linecap="round"/>'
    ),
}


def png_uri(svg: str, size: int) -> str:
    png = cairosvg.svg2png(bytestring=svg.encode(), output_width=size, output_height=size)
    return "data:image/png;base64," + base64.b64encode(png).decode()


def brand_icon(name: str) -> str:
    raw = open(os.path.join(ICONS, f"{name}.svg")).read()
    if name in BRAND:
        d = re.search(r'<path d="([^"]+)"', raw).group(1)
        raw = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
            f'<path d="{d}" fill="{BRAND[name]}"/></svg>'
        )
    return raw


def file_icon(name: str) -> str:
    return open(os.path.join(ICONS, f"{name}.svg")).read()


def generic_icon(name: str) -> str:
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">{GENERIC[name]}</svg>'


W, H = 1680, 920
CARD_W, CARD_H = 200, 150
FONT = "DejaVu Sans"

# id, x_center, y_center, icon svg, title, subtitle, dashed
NODES = [
    ("tenant", 150, 300, generic_icon("tenant"), "Tenant project", "untrusted Dockerfile", False),
    ("ctx", 150, 560, generic_icon("probe"), "Build context", "files and args", False),
    ("gen", 470, 430, generic_icon("gen"), "Probe generator", "10 attack classes", False),
    ("pack", 760, 300, generic_icon("probe"), "Probe pack", "Dockerfile + context", False),
    ("docker", 760, 560, brand_icon("docker"), "Docker Engine", "local builder", False),
    ("buildkit", 1050, 430, file_icon("buildkit"), "BuildKit / buildx", "runs each probe", False),
    ("parse", 1340, 300, generic_icon("parse"), "Log parser", "BB_FINDING markers", False),
    ("cloud", 1340, 560, file_icon("cloud"), "IMDS / egress", "reachability only", True),
    ("report", 1600, 240, generic_icon("report"), "Report", "text and JSON", False),
    ("github", 1600, 430, brand_icon("github"), "Code scanning", "SARIF 2.1.0", False),
    ("fix", 1600, 650, generic_icon("fix"), "Remediation", "network, secrets, jail", False),
]

EDGES = [
    ("tenant", "gen"),
    ("ctx", "gen"),
    ("gen", "pack"),
    ("gen", "docker"),
    ("pack", "buildkit"),
    ("docker", "buildkit"),
    ("buildkit", "parse"),
    ("buildkit", "cloud"),
    ("parse", "report"),
    ("parse", "github"),
    ("parse", "fix"),
]

COLUMNS = [
    (150, "INPUT"),
    (470, "GENERATE"),
    (760, "PROBE PACK"),
    (1050, "BUILD"),
    (1340, "DETECT"),
    (1600, "REPORT"),
]


def card(n) -> str:
    nid, cx, cy, icon, title, sub, dashed = n
    x, y = cx - CARD_W / 2, cy - CARD_H / 2
    dash = ' stroke-dasharray="8 6"' if dashed else ""
    stroke = "#0EA5E9" if dashed else "#CBD5E1"
    return "\n".join(
        [
            f'<rect x="{x}" y="{y}" width="{CARD_W}" height="{CARD_H}" rx="16" fill="#FFFFFF" '
            f'stroke="{stroke}" stroke-width="2"{dash} filter="url(#shadow)"/>',
            f'<image x="{cx - 32}" y="{y + 18}" width="64" height="64" href="{png_uri(icon, 128)}"/>',
            f'<text x="{cx}" y="{y + 108}" text-anchor="middle" font-family="{FONT}" font-size="17" '
            f'font-weight="bold" fill="#0F172A">{title}</text>',
            f'<text x="{cx}" y="{y + 132}" text-anchor="middle" font-family="{FONT}" font-size="13" '
            f'fill="#64748B">{sub}</text>',
        ]
    )


def edge(a, b, pos) -> str:
    _, ax, ay, *_ = pos[a]
    _, bx, by, *_ = pos[b]
    x1, x2 = ax + CARD_W / 2, bx - CARD_W / 2 - 6
    return (
        f'<path d="M{x1} {ay} C{x1 + 50} {ay}, {x2 - 50} {by}, {x2} {by}" fill="none" '
        f'stroke="#94A3B8" stroke-width="2.4" marker-end="url(#arrow)"/>'
    )


def diagram() -> str:
    pos = {n[0]: n for n in NODES}
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" '
        'orient="auto"><path d="M0 0L10 5L0 10z" fill="#94A3B8"/></marker>'
        '<filter id="shadow" x="-10%" y="-10%" width="120%" height="130%"><feDropShadow dx="0" dy="3" '
        'stdDeviation="4" flood-color="#0F172A" flood-opacity="0.12"/></filter></defs>',
        f'<rect width="{W}" height="{H}" fill="#F8FAFC"/>',
        f'<text x="{W / 2}" y="52" text-anchor="middle" font-family="{FONT}" font-size="28" '
        f'font-weight="bold" fill="#0F172A">Figure 1. BuildBreaker System Architecture</text>',
    ]
    for cx, label in COLUMNS:
        parts.append(
            f'<text x="{cx}" y="100" text-anchor="middle" font-family="{FONT}" font-size="13" '
            f'font-weight="bold" letter-spacing="1.5" fill="#94A3B8">{label}</text>'
        )
    for a, b in EDGES:
        parts.append(edge(a, b, pos))
    for n in NODES:
        parts.append(card(n))
    parts.append(
        f'<text x="{W / 2}" y="{H - 24}" text-anchor="middle" font-family="{FONT}" font-size="13" '
        f'fill="#94A3B8">Docker, GitHub and Linux icons: Simple Icons (CC0). BuildKit and cloud icons: project artwork.</text>'
    )
    parts.append("</svg>")
    return "\n".join(parts)


if __name__ == "__main__":
    svg = diagram()
    open(os.path.join(HERE, "architecture.svg"), "w").write(svg)
    cairosvg.svg2png(
        bytestring=svg.encode(),
        write_to=os.path.join(HERE, "architecture.png"),
        output_width=W * 2,
        output_height=H * 2,
    )
    logo = open(os.path.join(HERE, "logo.svg")).read()
    cairosvg.svg2png(
        bytestring=logo.encode(),
        write_to=os.path.join(HERE, "logo.png"),
        output_width=512,
        output_height=512,
    )
    print("rendered architecture.png, architecture.svg, logo.png")
