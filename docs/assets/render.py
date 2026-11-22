"""Render the BuildBreaker logo and architecture diagram (docs/assets/*.png).

Requires cairosvg. Icons: Simple Icons (CC0) for Docker, GitHub, Linux;
custom layer stack for BuildKit; custom cloud for IMDS.
"""

import base64
import os
import re

import cairosvg

from diagram_kit import CARD_H, CARD_W, FONT, arrow, band, card, defs, legend, pill

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


W, H = 1960, 900
BLUE = "#0284C7"
ACCENTS = {"flow": "#94A3B8", "net": BLUE}

# id: (cx, cy)
P = {
    "tenant": (170, 330), "ctx": (170, 530),
    "gen": (545, 430), "pack": (850, 430),
    "cloud": (1165, 200), "builder": (1165, 430),
    "parse": (1470, 430),
    "report": (1810, 230), "github": (1810, 430), "fix": (1810, 630),
}
HW, HH = CARD_W / 2, CARD_H / 2


def L(n):
    return P[n][0] - HW, P[n][1]


def R(n):
    return P[n][0] + HW, P[n][1]


def T(n):
    return P[n][0], P[n][1] - HH


def B(n):
    return P[n][0], P[n][1] + HH


def diagram() -> str:
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
             defs(ACCENTS), f'<rect width="{W}" height="{H}" fill="#FFFFFF"/>']
    top, bh = 40, 720
    for x, w, title in [(50, 240, "INPUTS"), (360, 640, "GENERATE"), (1045, 240, "BUILD"),
                        (1350, 240, "DETECT"), (1670, 280, "REPORT")]:
        parts.append(band(x, top, w, bh, title))

    labels = []
    bus_in = 418
    for n, lab in [("tenant", "Dockerfile"), ("ctx", "files, args")]:
        x1, y1 = R(n)
        parts.append(arrow([(x1, y1), (bus_in, y1), (bus_in, P["gen"][1]), (L("gen")[0] - 2, P["gen"][1])]))
        labels.append(pill((x1 + bus_in) / 2, y1, lab))
    for a, b, lab in [("gen", "pack", "10 probes"), ("pack", "builder", "build"), ("builder", "parse", "build logs")]:
        parts.append(arrow([R(a), (L(b)[0] - 2, P[b][1])]))
        labels.append(pill((R(a)[0] + L(b)[0]) / 2, P[a][1], lab))
    parts.append(arrow([T("builder"), (P["cloud"][0], B("cloud")[1] + 2)], accent="net", color=BLUE, dashed=True))
    labels.append(pill(P["builder"][0], (T("builder")[1] + B("cloud")[1]) / 2, "network test", color=BLUE,
                       border="#7DD3FC"))
    bus_out = 1615
    for n, lab in [("report", "JSON"), ("github", "SARIF"), ("fix", "fixes")]:
        y = P[n][1]
        parts.append(arrow([R("parse"), (bus_out, P["parse"][1]), (bus_out, y), (L(n)[0] - 2, y)]))
        labels.append(pill((bus_out + L(n)[0]) / 2, y, lab))

    cards = [
        ("tenant", generic_icon("tenant"), "Tenant project", "untrusted Dockerfile", {}),
        ("ctx", generic_icon("probe"), "Build context", "files and args", {}),
        ("gen", generic_icon("gen"), "Probe generator", "10 attack classes", {}),
        ("pack", generic_icon("probe"), "Probe pack", "plus canary token", {}),
        ("cloud", file_icon("cloud"), "Cloud metadata", "and internet reach", {"border": BLUE, "dashed": True}),
        ("builder", file_icon("buildkit"), "BuildKit", "builder under test", {"badge_svg": brand_icon("docker")}),
        ("parse", generic_icon("parse"), "Log parser", "reads build findings", {}),
        ("report", generic_icon("report"), "Report", "CI exit code gate", {}),
        ("github", brand_icon("github"), "Code scanning", "SARIF alerts", {}),
        ("fix", generic_icon("fix"), "Remediation", "network, secrets, paths", {}),
    ]
    for n, icon, title, sub, kw in cards:
        parts.append(card(*P[n], icon, title, sub, **kw))
    parts.extend(labels)

    leg, end = legend(0, 0, [
        ("line", ("#94A3B8", False, "flow"), "data flow"),
        ("line", (BLUE, True, "net"), "network reach test"),
        ("card", (BLUE, True), "outside the builder"),
        ("icon", generic_icon("gen"), "BuildBreaker component"),
        ("icon", brand_icon("docker"), "external product"),
    ])
    lx = (W - end + 44) / 2
    parts.append(f'<g transform="translate({lx} 815)">{leg}</g>')
    parts.append(f'<text x="{W / 2}" y="{H - 24}" text-anchor="middle" font-family="{FONT}" font-size="13" '
                 f'fill="#94A3B8">Docker and GitHub icons: Simple Icons (CC0). BuildKit and cloud icons: '
                 f'project artwork.</text>')
    parts.append("</svg>")
    return "\n".join(parts)


if __name__ == "__main__":
    svg = diagram()
    open(os.path.join(HERE, "architecture.svg"), "w").write(svg)
    cairosvg.svg2png(bytestring=svg.encode(), write_to=os.path.join(HERE, "architecture.png"),
                     output_width=W * 2, output_height=H * 2)
    logo = open(os.path.join(HERE, "logo.svg")).read()
    cairosvg.svg2png(bytestring=logo.encode(), write_to=os.path.join(HERE, "logo.png"),
                     output_width=512, output_height=512)
    print("rendered architecture.png, architecture.svg, logo.png")
