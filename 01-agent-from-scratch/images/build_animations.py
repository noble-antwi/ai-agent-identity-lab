"""Build the animated diagrams from the static ones (SMIL animation, plays on GitHub). Edit the static SVG, then re-run."""
from pathlib import Path

IMG = Path(__file__).resolve().parent  # run from anywhere: python images/build_animations.py


def f(x):
    return f"{x:.3f}".rstrip("0").rstrip(".") if x else "0"


def window(a, b, D, eps=0.012):
    """opacity animate: visible between fractions a and b of the loop."""
    vals = "0;0;1;1;0;0"
    kt = ";".join(f(t) for t in (0, a - eps, a, b, b + eps, 1))
    return f'<animate attributeName="opacity" dur="{D}s" repeatCount="indefinite" values="{vals}" keyTimes="{kt}"/>'


def windows(spans, D, eps=0.012):
    vals, kts = ["0"], [0.0]
    for a, b in spans:
        vals += ["0", "1", "1", "0"]
        kts += [a - eps, a, b, b + eps]
    vals.append("0")
    kts.append(1.0)
    return (f'<animate attributeName="opacity" dur="{D}s" repeatCount="indefinite" '
            f'values="{";".join(vals)}" keyTimes="{";".join(f(t) for t in kts)}"/>')


def mover(path, s, e, color, label, lw, D, lx=0, ly=-30):
    return f'''
  <g opacity="0">
    <animateMotion path="{path}" dur="{D}s" repeatCount="indefinite" calcMode="linear" keyPoints="0;0;1;1" keyTimes="0;{f(s)};{f(e)};1"/>
    {window(s, e, D)}
    <circle r="10" fill="{color}" opacity="0.3"><animate attributeName="r" values="8;15;8" dur="0.9s" repeatCount="indefinite"/></circle>
    <circle r="6" fill="{color}" stroke="#FFFFFF" stroke-width="2"/>
    <rect x="{lx - lw / 2}" y="{ly}" width="{lw}" height="19" rx="9.5" fill="#08152F"/>
    <text x="{lx}" y="{ly + 13.5}" font-size="10.5" font-weight="700" fill="#FFFFFF" text-anchor="middle">{label}</text>
  </g>'''


def ring(cx, cy, r0, r1, color, spans, D):
    return f'''
  <g opacity="0">{windows(spans, D)}
    <circle cx="{cx}" cy="{cy}" r="{r0}" fill="none" stroke="{color}" stroke-width="2.5">
      <animate attributeName="r" values="{r0};{r1}" dur="0.9s" repeatCount="indefinite"/>
      <animate attributeName="stroke-opacity" values="0.9;0" dur="0.9s" repeatCount="indefinite"/>
    </circle>
  </g>'''


def progress(D, y):
    return (f'<rect x="0.5" y="{y}" width="0" height="3" fill="#2DD4E8">'
            f'<animate attributeName="width" values="0;959" dur="{D}s" repeatCount="indefinite"/></rect>')


# ---------------------------------------------------------------- flow
D = 18
flow = (IMG / "agent-flow.svg").read_text(encoding="utf-8")
flow = flow.replace("Ask my SIEM</text>", "Ask my SIEM</text>", 1)

CYAN, GREEN, AMBER = "#0E7490", "#0F6E56", "#D98E04"
steps = {  # step: (start, end) of its highlight window
    1: (0.02, 0.10), 2: (0.10, 0.26), 3: (0.26, 0.38), 4: (0.38, 0.48),
    5: (0.48, 0.66), 6: (0.66, 0.80), 7: (0.80, 0.90), 8: (0.90, 0.985),
}
rows = {1: (38, 456), 2: (38, 488), 3: (38, 520), 4: (38, 552),
        5: (498, 456), 6: (498, 488), 7: (498, 520), 8: (498, 552)}
hl = "\n  <!-- Animated step highlights -->"
for n, (a, b) in steps.items():
    x, y = rows[n]
    hl += (f'\n  <rect x="{x}" y="{y}" width="436" height="26" rx="13" fill="#D6EEF4" opacity="0">'
           f'{window(a, b, D)}</rect>')
flow = flow.replace("  <!-- Steps -->", hl + "\n  <!-- Steps -->", 1)

alerts_hl = (f'  <rect x="666" y="303" width="230" height="22" rx="6" fill="#CDEFE2" opacity="0">'
             f'{window(0.48, 0.60, D)}</rect>\n')
flow = flow.replace('  <text x="674" y="318"', alerts_hl + '  <text x="674" y="318"', 1)

layer = "\n  <!-- Motion layer -->"
layer += "\n  " + progress(D, 82)
layer += f'''
  <rect x="568" y="230" width="82" height="20" rx="10" fill="none" stroke="#2DD4E8" stroke-width="3" opacity="0">{windows([(0.38, 0.48), (0.56, 0.64)], D)}</rect>'''
layer += ring(149, 192, 26, 44, CYAN, [(0.20, 0.26), (0.74, 0.80)], D)
layer += ring(781, 276, 18, 70, GREEN, [(0.48, 0.56)], D)
layer += mover("M450 352 V330", 0.03, 0.08, CYAN, "question", 70, D, lx=86, ly=-10)
layer += mover("M332 210 H250", 0.11, 0.20, CYAN, "question + menu", 108, D)
layer += mover("M250 270 H332", 0.27, 0.36, CYAN, "search WKS01, 24h", 118, D, ly=12)
layer += mover("M568 240 H700 V262", 0.39, 0.48, CYAN, "as svc-ask-siem", 108, D)
layer += mover("M700 262 V240 H568", 0.56, 0.64, GREEN, "50 newest alerts", 112, D, ly=12)
layer += mover("M332 210 H250", 0.67, 0.74, GREEN, "the alerts", 76, D)
layer += mover("M250 270 H332", 0.81, 0.88, AMBER, "the answer", 78, D, ly=12)
layer += mover("M450 330 V352", 0.91, 0.96, AMBER, "the answer", 78, D, lx=92, ly=-10)
flow = flow.replace("</svg>", layer + "\n</svg>")
(IMG / "agent-flow-animated.svg").write_text(flow, encoding="utf-8")

# ---------------------------------------------------------------- doors
D2 = 11
doors = (IMG / "agent-doors.svg").read_text(encoding="utf-8")
bubble_start = doors.index("  <!-- Speech bubble -->")
bubble_end = doors.index('  <text x="444" y="402"')
bubble = doors[bubble_start:bubble_end]
doors = (doors[:bubble_start]
         + f'  <g opacity="0">{window(0.70, 0.96, D2)}\n' + bubble + "  </g>\n"
         + doors[bubble_end:])

layer = "\n  <!-- Motion layer -->"
layer += "\n  " + progress(D2, 82)
layer += mover("M270 205 H408", 0.05, 0.20, "#B0422A", "192.168.20.2:9200", 120, D2)
layer += f'''
  <g opacity="0">{window(0.20, 0.32, D2)}
    <line x1="406" y1="191" x2="434" y2="219" stroke="#B0422A" stroke-width="5"/>
    <line x1="434" y1="191" x2="406" y2="219" stroke="#B0422A" stroke-width="5"/>
  </g>'''
layer += ring(420, 205, 10, 34, "#B0422A", [(0.20, 0.30)], D2)
layer += f'''
  <rect x="406" y="306" width="28" height="54" rx="4" fill="none" stroke="#2DD4E8" stroke-width="3" opacity="0">{window(0.43, 0.50, D2)}</rect>'''
layer += mover("M270 333 H640 V232 H690", 0.38, 0.68, "#0E7490", "localhost:9200", 98, D2, ly=12)
layer += f'''
  <rect x="686" y="172" width="208" height="120" rx="12" fill="none" stroke="#2DD4E8" stroke-width="3" opacity="0">{window(0.68, 0.96, D2)}</rect>'''
doors = doors.replace("</svg>", layer + "\n</svg>")
(IMG / "agent-doors-animated.svg").write_text(doors, encoding="utf-8")
print("ok")
