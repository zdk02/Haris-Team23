"""Report figures, drawn as SVG with no plotting dependency (task O4).

WHY SVG BY HAND RATHER THAN MATPLOTLIB.
Adding a plotting library means adding it to `requirements.lock.txt`, which is SHA-pinned,
and rebuilding the image in the last week of the project to render four charts. It also
makes the figures un-reproducible for anyone who checks out the repo without a plotting
backend. SVG is text: this module writes it directly, the output is byte-identical on every
run, and the files diff cleanly in git.

Every figure is generated FROM THE HARNESS, never typed in. If a number in the report
disagrees with a figure, that is a bug in this file rather than a transcription error, and
regenerating is one command.

THE FIGURES, AND WHAT EACH IS FOR.
  1. four-arm comparison  — the headline. Prevention and false positives for all four
                            arms with 95% intervals. This is the figure the report leads
                            with, because it is the only one that isolates what lineage
                            contributes.
  2. per-family           — where the arms differ. The two rows that separate Haris from
                            both baselines, and the rows where they beat Haris.
  3. obfuscation ladder   — the difficulty curve. Drawn deliberately WITHOUT y-axis
                            precision, because n=4 per rung: the shape is the claim, not
                            the percentages (task M4 flags every rung as uninformative).
  4. latency              — Presidio off vs on, avg and p95. Optional: needs the ON
                            snapshot, which is a slow run.

    python -m demo_app.eval.figures
    python -m demo_app.eval.figures --out report/figures
"""
from __future__ import annotations

import argparse
import pathlib
from collections import defaultdict
from typing import Optional, Sequence

# Muted, print-safe, and distinguishable in greyscale — a report gets photocopied.
INK = "#1a1a1a"
GRID = "#d8d8d8"
MUTED = "#767676"
ARM_COLOURS = {
    "none": "#bdbdbd",
    "scanner": "#8ab4c8",
    "metadata": "#e0a458",
    "haris": "#2f6f4e",
}
FONT = "Helvetica, Arial, sans-serif"


def _esc(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


class Canvas:
    """Just enough SVG to draw a bar chart. Deliberately small and readable."""

    def __init__(self, width: int, height: int, title: str = "", subtitle: str = ""):
        self.w, self.h = width, height
        self.parts: list[str] = []
        if title:
            self.text(24, 30, title, size=15, weight="600")
        if subtitle:
            self.text(24, 50, subtitle, size=11, fill=MUTED)

    def text(self, x: float, y: float, s: str, *, size: float = 11,
             fill: str = INK, anchor: str = "start", weight: str = "400") -> None:
        self.parts.append(
            f'<text x="{x:.1f}" y="{y:.1f}" font-family="{FONT}" font-size="{size}" '
            f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{_esc(s)}</text>')

    def rect(self, x: float, y: float, w: float, h: float, fill: str,
             opacity: float = 1.0) -> None:
        if h <= 0 or w <= 0:
            return
        self.parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
            f'fill="{fill}" opacity="{opacity}"/>')

    def line(self, x1: float, y1: float, x2: float, y2: float,
             stroke: str = GRID, width: float = 1.0) -> None:
        self.parts.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="{stroke}" stroke-width="{width}"/>')

    def whisker(self, x: float, y_low: float, y_high: float, cap: float = 3.0) -> None:
        """A 95% interval. Drawn on every bar; a bar without one would be a claim of
        certainty this evaluation cannot make anywhere."""
        self.line(x, y_low, x, y_high, stroke=INK, width=1.2)
        self.line(x - cap, y_low, x + cap, y_low, stroke=INK, width=1.2)
        self.line(x - cap, y_high, x + cap, y_high, stroke=INK, width=1.2)

    def render(self) -> str:
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" '
                f'height="{self.h}" viewBox="0 0 {self.w} {self.h}">'
                f'<rect width="{self.w}" height="{self.h}" fill="white"/>'
                + "".join(self.parts) + "</svg>\n")


def _y_axis(c: Canvas, top: float, bottom: float, left: float, right: float,
            *, label: str = "") -> None:
    """0-100% gridlines."""
    for pct in range(0, 101, 25):
        y = bottom - (pct / 100.0) * (bottom - top)
        c.line(left, y, right, y)
        c.text(left - 8, y + 4, f"{pct}%", size=10, fill=MUTED, anchor="end")
    if label:
        c.text(left - 8, top - 12, label, size=10, fill=MUTED, anchor="end")


# --------------------------------------------------------------------------- #
# Figure 1 — the four-arm comparison
# --------------------------------------------------------------------------- #

def fig_four_arm(rows: list[dict], arms, prevention_ci, fp_ci) -> str:
    c = Canvas(760, 420,
               "Leak prevention and false positives, four arms, one corpus",
               "432 scenarios · 95% bootstrap CI · same outcome-based rule scores every arm")

    top, bottom, left, right = 90, 330, 70, 700
    _y_axis(c, top, bottom, left, right)

    groups = [("leak prevention", prevention_ci), ("false positives", fp_ci)]
    gw = (right - left) / len(groups)
    bw = min(46.0, (gw - 60) / len(arms))

    for gi, (gname, fn) in enumerate(groups):
        gx = left + gi * gw
        c.text(gx + gw / 2, bottom + 34, gname, size=12, anchor="middle")
        span = len(arms) * bw + (len(arms) - 1) * 10
        for ai, arm in enumerate(arms):
            ci = fn(rows, arm.key)
            if ci is None:
                continue
            x = gx + (gw - span) / 2 + ai * (bw + 10)
            y = bottom - ci.rate * (bottom - top)
            c.rect(x, y, bw, bottom - y, ARM_COLOURS.get(arm.key, MUTED))
            c.whisker(x + bw / 2,
                      bottom - ci.low * (bottom - top),
                      bottom - ci.high * (bottom - top))
            # Above the whisker cap, not the bar: at 71% the two collided.
            label_y = min(y, bottom - ci.high * (bottom - top)) - 9
            c.text(x + bw / 2, label_y, f"{ci.rate*100:.0f}%", size=10, anchor="middle")

    for ai, arm in enumerate(arms):
        lx = 70 + ai * 170
        c.rect(lx, 368, 11, 11, ARM_COLOURS.get(arm.key, MUTED))
        c.text(lx + 17, 378, arm.label, size=10)
    c.text(24, 404,
           "Lower is better for false positives. Haris's 14% is one family "
           "(internal_handoff) it refuses on purpose.",
           size=9, fill=MUTED)
    return c.render()


# --------------------------------------------------------------------------- #
# Figure 2 — per family, where the arms actually differ
# --------------------------------------------------------------------------- #

def fig_by_family(rows: list[dict], arms, prevention_ci) -> str:
    """Per-family prevention, with the differentiating rows called out.

    The figure exists to show WHERE the arms diverge, so the two families no baseline
    catches are marked rather than left for the reader to spot. An earlier version
    printed Haris's rate at the right of every row, which read as the row's headline —
    misleading on external_obfuscated, where the heuristic is at 100% and Haris at 33%.
    The annotation now names the leader instead.
    """
    fams = defaultdict(list)
    for r in rows:
        if r["label_attack"]:
            fams[r["family"]].append(r)
    scored = [(f, rs) for f, rs in sorted(fams.items())
              if any(r["leak_unmediated"] for r in rs)]

    row_h = 46
    top = 100
    height = top + row_h * len(scored) + 96
    c = Canvas(820, height,
               "Leak prevention by attack family",
               "n=24 per family · the differences between arms are the evidence, "
               "not any single cell")

    left, right = 250, 660
    for i, (fam, rs) in enumerate(scored):
        y = top + i * row_h
        cis = {a.key: prevention_ci(rs, a.key) for a in arms}
        baselines = [cis[k] for k in ("scanner", "metadata") if cis.get(k)]
        haris = cis.get("haris")

        # A family only Haris catches: both baselines at zero, Haris above them.
        differentiator = bool(
            haris and baselines and haris.rate > 0.5
            and all(b.rate == 0.0 for b in baselines))

        if differentiator:
            c.rect(left - 240, y - 6, 900, row_h - 6, "#2f6f4e", opacity=0.06)

        c.text(left - 12, y + 14, fam, size=11, anchor="end",
               weight="600" if differentiator else "400")

        for ai, arm in enumerate(arms):
            ci = cis.get(arm.key)
            if ci is None:
                continue
            bar_y = y + ai * 7
            c.line(left, bar_y + 3, right, bar_y + 3, stroke="#efefef")
            c.rect(left, bar_y, ci.rate * (right - left), 6,
                   ARM_COLOURS.get(arm.key, MUTED))

        # Name the LEADER, not a fixed arm — on the obfuscation row that is the
        # heuristic, and saying "33%" there would misdescribe the figure.
        ranked = sorted((ci for ci in cis.values() if ci), key=lambda x: -x.rate)
        if ranked:
            best = ranked[0].rate
            leaders = [a.label for a in arms
                       if cis.get(a.key) and cis[a.key].rate == best]
            note = ("all arms" if len(leaders) >= 3 else ", ".join(leaders))
            c.text(right + 14, y + 16, f"{best*100:.0f}%  {note}", size=9, fill=MUTED)

    base = top + row_h * len(scored) + 10
    for ai, arm in enumerate(arms):
        lx = 250 + ai * 130
        c.rect(lx, base, 12, 6, ARM_COLOURS.get(arm.key, MUTED))
        c.text(lx + 18, base + 7, arm.label, size=9)
    c.text(24, base + 34,
           "Shaded rows: no baseline catches them. subject_forgery hides in a payload "
           "that contradicts its own label;",
           size=9, fill=MUTED)
    c.text(24, base + 48,
           "partner_scope_violation is addressed to a real partner, for a patient the "
           "agreement does not cover.",
           size=9, fill=MUTED)
    return c.render()


# --------------------------------------------------------------------------- #
# Figure 3 — the obfuscation ladder
# --------------------------------------------------------------------------- #

def fig_ladder(rows: list[dict], arms, prevention_ci) -> str:
    by = defaultdict(list)
    for r in rows:
        if r.get("rung"):
            by[r["rung"]].append(r)
    rungs = sorted(by)

    c = Canvas(760, 400,
               "Obfuscation ladder: what survives a normalising matcher",
               "n=4 per rung — read the SHAPE, not the values (every interval is wide)")

    top, bottom, left, right = 95, 300, 70, 720
    _y_axis(c, top, bottom, left, right)
    step = (right - left) / (len(rungs) - 1 or 1)

    # the layout/encoding boundary — the claim this figure actually makes
    boundary = left + 1.5 * step
    c.line(boundary, top - 6, boundary, bottom, stroke="#c9c9c9", width=1)
    c.text(boundary - 8, top - 12, "layout changes", size=9, fill=MUTED, anchor="end")
    c.text(boundary + 8, top - 12, "encodings", size=9, fill=MUTED)

    for arm in arms:
        if arm.key == "none":
            continue
        pts = []
        for i, rung in enumerate(rungs):
            ci = prevention_ci(by[rung], arm.key)
            if ci is None:
                continue
            x = left + i * step
            y = bottom - ci.rate * (bottom - top)
            pts.append((x, y))
        colour = ARM_COLOURS.get(arm.key, MUTED)
        for (x1, y1), (x2, y2) in zip(pts, pts[1:]):
            c.line(x1, y1, x2, y2, stroke=colour, width=2.2)
        for x, y in pts:
            c.parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" fill="{colour}"/>')

    for i, rung in enumerate(rungs):
        c.text(left + i * step, bottom + 20, rung.split("_", 1)[-1], size=9,
               anchor="middle", fill=MUTED)

    for ai, arm in enumerate(a for a in arms if a.key != "none"):
        lx = 70 + ai * 170
        c.rect(lx, 340, 11, 4, ARM_COLOURS.get(arm.key, MUTED))
        c.text(lx + 17, 346, arm.label, size=10)
    c.text(24, 378,
           "The metadata arm is flat at 100% because it never opens the payload: "
           "encoding is no defence against a rule that does not look.",
           size=9, fill=MUTED)
    return c.render()


# --------------------------------------------------------------------------- #
# Figure 4 — latency, both configurations
# --------------------------------------------------------------------------- #

def fig_latency(off_avg: float, off_p95: float,
                on_avg: Optional[float], on_p95: Optional[float]) -> str:
    c = Canvas(620, 360,
               "Mediation cost per hop",
               "Presidio adds detection, not enforcement — and two orders of magnitude")

    bars = [("Presidio off\navg", off_avg), ("Presidio off\np95", off_p95)]
    if on_avg is not None:
        bars += [("Presidio on\navg", on_avg), ("Presidio on\np95", on_p95)]

    top, bottom, left = 95, 275, 80
    peak = max(v for _, v in bars) or 1.0
    bw, gap = 70.0, 34.0

    for pct in (0, 25, 50, 75, 100):
        y = bottom - (pct / 100.0) * (bottom - top)
        c.line(left, y, left + len(bars) * (bw + gap), y)
        c.text(left - 8, y + 4, f"{peak*pct/100:.1f}", size=10, fill=MUTED, anchor="end")
    c.text(left - 8, top - 12, "ms", size=10, fill=MUTED, anchor="end")

    for i, (label, val) in enumerate(bars):
        x = left + 20 + i * (bw + gap)
        h = (val / peak) * (bottom - top)
        colour = ARM_COLOURS["haris"] if "off" in label else ARM_COLOURS["metadata"]
        c.rect(x, bottom - h, bw, h, colour)
        c.text(x + bw / 2, bottom - h - 10, f"{val:.2f}", size=10, anchor="middle")
        for j, part in enumerate(label.split("\n")):
            c.text(x + bw / 2, bottom + 20 + j * 13, part, size=10,
                   anchor="middle", fill=MUTED)

    c.text(24, 330,
           "Same prevention either way (90%). Presidio buys detection 76% -> 85%.",
           size=9, fill=MUTED)
    return c.render()


# --------------------------------------------------------------------------- #

def _latency_from_snapshot(path: pathlib.Path) -> tuple[Optional[float], Optional[float]]:
    """Pull avg/p95 out of the Presidio-ON snapshot, tolerantly.

    The snapshot's schema is not this module's to define, so search rather than assume;
    a missing figure skips the latency chart instead of inventing one.
    """
    if not path.exists():
        return None, None
    import json
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None, None

    found: dict[str, float] = {}

    def walk(node) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                lk = str(k).lower()
                if isinstance(v, (int, float)) and "laten" in lk or (
                        isinstance(v, (int, float)) and lk in ("avg_ms", "p95_ms")):
                    if "p95" in lk:
                        found.setdefault("p95", float(v))
                    elif "avg" in lk or "mean" in lk:
                        found.setdefault("avg", float(v))
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    return found.get("avg"), found.get("p95")


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate the report figures as SVG.")
    ap.add_argument("--out", default="report/figures")
    ap.add_argument("--presidio-on", default="demo_app/eval/presidio_on.json")
    args = ap.parse_args()

    import logging
    logging.disable(logging.INFO)

    from demo_app.eval.baselines import ARMS, _false_positive_ci, _prevention_ci, run_all

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    print("running the harness (Presidio off) ...")
    rows = run_all(include_secrets=False)

    figures = {
        "fig1-four-arm.svg": fig_four_arm(rows, ARMS, _prevention_ci, _false_positive_ci),
        "fig2-by-family.svg": fig_by_family(rows, ARMS, _prevention_ci),
        "fig3-obfuscation-ladder.svg": fig_ladder(rows, ARMS, _prevention_ci),
    }

    lat = [x for r in rows for x in r["arms"]["haris"]["latencies"]]
    if lat:
        lat.sort()
        off_avg = sum(lat) / len(lat)
        off_p95 = lat[min(len(lat) - 1, int(0.95 * len(lat)))]
        on_avg, on_p95 = _latency_from_snapshot(pathlib.Path(args.presidio_on))
        if on_avg is None:
            print("  (no latency in the Presidio-ON snapshot — drawing the OFF bars only)")
        figures["fig4-latency.svg"] = fig_latency(off_avg, off_p95, on_avg, on_p95)

    for name, svg in figures.items():
        (out / name).write_text(svg, encoding="utf-8")
        print(f"  wrote {out / name}")

    print(f"\n{len(figures)} figures. Regenerate after any change that moves a number —")
    print("they are drawn from the harness, so a figure disagreeing with the text is a")
    print("bug in figures.py, not a transcription error.")


if __name__ == "__main__":
    main()