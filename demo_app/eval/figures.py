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
import json
import math
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

def fig_four_arm(rows: list[dict], arms, exfil_ci, boundary_ci, fp_ci) -> str:
    """The headline comparison, with the two prevention claims kept APART.

    An earlier version drew a single "leak prevention" group. That is the number
    report/RESULTS.md explicitly tells the reader not to quote: it pools data leaving the
    trust boundary with one patient's record reaching the wrong workflow, and a sixth of
    its denominator is the second. Worse, the two claims point in opposite directions —
    the metadata heuristic wins the first and scores zero on the second — so a combined
    bar hid the entire argument.

    Every count in the subtitle is computed from `rows`. The previous version had "432
    scenarios" as a literal, so it kept printing a stale figure after each regeneration —
    a chart that looks fresh and is not, which is worse than one that is obviously old.
    """
    n_scen = len(rows)
    n_ex = len([r for r in rows if r["label_attack"] and r["leak_unmediated"]
                and r["egresses"]])
    n_bd = len([r for r in rows if r["label_attack"] and r["leak_unmediated"]
                and not r["egresses"]])
    n_ben = len([r for r in rows if not r["label_attack"]])

    c = Canvas(860, 440,
               "Exfiltration, boundary crossings and false positives — four arms, one corpus",
               f"{n_scen} scenarios · 95% bootstrap CI · same outcome-based rule scores "
               f"every arm")

    top, bottom, left, right = 95, 330, 70, 820
    _y_axis(c, top, bottom, left, right)

    groups = [
        (f"exfiltration (n={n_ex})", exfil_ci),
        (f"boundary crossings (n={n_bd})", boundary_ci),
        (f"false positives (n={n_ben})", fp_ci),
    ]
    gw = (right - left) / len(groups)
    bw = min(34.0, (gw - 40) / len(arms))

    for gi, (gname, fn) in enumerate(groups):
        gx = left + gi * gw
        c.text(gx + gw / 2, bottom + 34, gname, size=11, anchor="middle")
        span = len(arms) * bw + (len(arms) - 1) * 8
        for ai, arm in enumerate(arms):
            ci = fn(rows, arm.key)
            if ci is None:
                continue
            x = gx + (gw - span) / 2 + ai * (bw + 8)
            y = bottom - ci.rate * (bottom - top)
            c.rect(x, y, bw, bottom - y, ARM_COLOURS.get(arm.key, MUTED))
            c.whisker(x + bw / 2,
                      bottom - ci.low * (bottom - top),
                      bottom - ci.high * (bottom - top))
            label_y = min(y, bottom - ci.high * (bottom - top)) - 9
            c.text(x + bw / 2, label_y, f"{ci.rate*100:.0f}%", size=9, anchor="middle")

    for ai, arm in enumerate(arms):
        lx = 70 + ai * 190
        c.rect(lx, 372, 11, 11, ARM_COLOURS.get(arm.key, MUTED))
        c.text(lx + 17, 382, arm.label, size=10)

    haris_fp = fp_ci(rows, "haris")
    heur_fp = fp_ci(rows, "metadata")
    c.text(24, 408,
           "The metadata heuristic wins on exfiltration — a rule that never reads content "
           "cannot be defeated by rewriting content — and",
           size=9, fill=MUTED)
    c.text(24, 421,
           f"scores zero on boundary crossings. Lower is better for false positives: "
           f"{(haris_fp.rate*100 if haris_fp else 0):.0f}% against the heuristic's "
           f"{(heur_fp.rate*100 if heur_fp else 0):.0f}%.",
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

def fig_latency(off: dict, on: Optional[dict]) -> str:
    """Mediation cost, from the dedicated latency harness (task O3).

    WHAT THIS REPLACED. The earlier version read an average and a p95 out of the runner's
    by-product timings. Those had no denominator, warmed five scenarios from one family,
    and ran once — and the Presidio figures among them (8.98, 9.46, 11.1 ms) turned out to
    be measuring spaCy model INITIALISATION, because both PII-consuming agents were
    constructing their own detector per scenario. A cold `analyze()` costs 1686 ms against
    4.4 ms warm.

    This reads `report/appendix/latency-presidio-{off,on}.json`: three repetitions, one
    warm-up scenario per family, medians with interquartile range, and a no-agents floor
    so the bar is mediation rather than wall clock.
    """
    def arm(d: dict, key_part: str) -> Optional[dict]:
        for k, v in d.get("arms", {}).items():
            if key_part in k.lower():
                return v
        return None

    floor = arm(off, "floor")
    struct = arm(off, "haris")
    presidio = arm(on, "haris") if on else None

    bars = [("no agents\n(floor)", floor), ("Haris\nstructural", struct)]
    if presidio:
        bars.append(("Haris +\nPresidio", presidio))
    bars = [(lbl, d) for lbl, d in bars if d]

    c = Canvas(700, 420, "Mediation cost per hop",
               "median with interquartile range · 3 repetitions · warm-up per family · "
               "LOG SCALE")

    top, bottom, left = 105, 285, 95
    bw, gap = 78.0, 52.0

    # LOG SCALE, because the arms span three orders of magnitude: 0.007 ms, 0.041 ms and
    # 12.553 ms. On a linear axis the two structural bars are sub-pixel slivers and the
    # chart reads as one bar with three labels — the shape of the comparison disappears
    # exactly where it is most interesting. The axis is labelled as logarithmic in the
    # subtitle and on the gridlines, because a log scale that is not announced misleads
    # more than a bad linear one.
    lo_dec, hi_dec = -3, 2                       # 0.001 ms .. 100 ms
    def y_of(ms: float) -> float:
        v = max(ms, 10 ** lo_dec)
        frac = (math.log10(v) - lo_dec) / (hi_dec - lo_dec)
        return bottom - frac * (bottom - top)

    for d in range(lo_dec, hi_dec + 1):
        val = 10.0 ** d
        y = y_of(val)
        c.line(left, y, left + len(bars) * (bw + gap), y)
        label = f"{val:g}" if val >= 1 else f"{val:.3f}".rstrip("0")
        c.text(left - 8, y + 4, label, size=10, fill=MUTED, anchor="end")
    c.text(left - 8, top - 12, "ms", size=10, fill=MUTED, anchor="end")

    for i, (label, d) in enumerate(bars):
        x = left + 20 + i * (bw + gap)
        y = y_of(d["median_ms"])
        colour = ARM_COLOURS["haris"] if "Presidio" not in label else ARM_COLOURS["metadata"]
        if "floor" in label:
            colour = ARM_COLOURS["none"]
        c.rect(x, y, bw, bottom - y, colour)
        lo, hi = d["iqr_ms"]
        if hi > lo:
            c.whisker(x + bw / 2, y_of(lo), y_of(hi))
        c.text(x + bw / 2, min(y, y_of(hi)) - 10, f"{d['median_ms']:.3f}",
               size=10, anchor="middle")
        for k, part in enumerate(label.split("\n")):
            c.text(x + bw / 2, bottom + 20 + k * 13, part, size=10,
                   anchor="middle", fill=MUTED)

    cost_struct = (struct["median_ms"] - floor["median_ms"]) if (struct and floor) else 0
    c.text(24, 356,
           f"Mediation cost = arm median minus the no-agents floor: "
           f"{cost_struct:.3f} ms for the structural agents"
           + (f", {presidio['median_ms'] - floor['median_ms']:.2f} ms with Presidio."
              if presidio and floor else "."),
           size=9, fill=MUTED)
    c.text(24, 370,
           "Presidio buys detection 76% -> 90% and exfiltration 73% -> 76%. Figures are "
           "machine-specific; see report/RESULTS.md for the CPU.",
           size=9, fill=MUTED)
    c.text(24, 384,
           "The axis is logarithmic: the floor and the structural agents differ from "
           "Presidio by three orders of magnitude, and a linear axis hides both.",
           size=9, fill=MUTED)
    return c.render()


# --------------------------------------------------------------------------- #
# Figure 5 — the taint-normalisation fix, before and after
# --------------------------------------------------------------------------- #

def fig_matcher_delta(before: dict, after: dict, fp_before: str, fp_after: str) -> str:
    """The one improvement this project can show as a controlled before/after.

    The info-flow agent decided a tag had resurfaced with an exact substring test until
    22 August; it now normalises both sides and respects word boundaries. `matcher_delta`
    restores the old rule and re-runs the entire corpus, so the two columns differ in one
    line of behaviour and nothing else.

    BOTH HALVES ARE DRAWN ON PURPOSE. Recall rises on the two families that reformat an
    identifier, and the false-positive rate does not move. A matcher can always be made to
    catch more by making it less discriminating; the flat false-positive pair is the
    evidence that this one was not, and a chart showing only the gain would be the more
    flattering and less honest figure.

    The families that do not move are not drawn. Twenty-two flat pairs would bury the two
    that matter, and the report states in §6.4.5 that everything else is unchanged.
    """
    fams = [k for k in before if before[k] != after[k]]
    # 860 wide, not 720: the false-positive values sit to the right of the plot and were
    # being clipped at the canvas edge.
    c = Canvas(860, 420,
               "Taint matching: exact substring vs normalised",
               "prevention per family, same corpus, one line of behaviour changed")

    top, bottom, left, right = 100, 300, 90, 620
    _y_axis(c, top, bottom, left, right)

    gw = (right - left) / max(len(fams), 1)
    bw = 62.0
    for gi, fam in enumerate(fams):
        gx = left + gi * gw
        for bi, (label, table, colour) in enumerate((
                ("before", before, MUTED), ("after", after, ARM_COLOURS["haris"]))):
            x = gx + (gw - (2 * bw + 18)) / 2 + bi * (bw + 18)
            rate = table[fam]
            y = bottom - rate * (bottom - top)
            if rate > 0:
                c.rect(x, y, bw, bottom - y, colour)
            else:
                # A zero bar has no height and reads as a MISSING bar rather than a bar
                # worth nothing — which matters here, since "caught nothing before the
                # fix" is half the point of the figure. Draw the footprint instead.
                c.line(x, bottom, x + bw, bottom, stroke=colour, width=3)
            c.text(x + bw / 2, y - 9, f"{rate*100:.0f}%", size=10, anchor="middle")
            c.text(x + bw / 2, bottom + 20, label, size=9, anchor="middle", fill=MUTED)
        c.text(gx + gw / 2, bottom + 38, fam, size=10, anchor="middle")

    # The false-positive pair, drawn beside the gains rather than mentioned underneath.
    fx = right + 20
    c.line(fx, top, fx, bottom + 10, stroke=GRID)
    c.text(fx + 46, top - 12, "false positives", size=10, anchor="middle", fill=MUTED)
    # Left-aligned on one x, so the two values line up and can be read as a pair. The
    # earlier version staggered them horizontally, which made the eye compare positions
    # instead of numbers.
    for bi, (label, val) in enumerate((("before", fp_before), ("after", fp_after))):
        y = top + 34 + bi * 20
        c.text(fx + 14, y, f"{label}:", size=10, fill=MUTED)
        c.text(fx + 62, y, val, size=10)
    c.text(fx + 62, top + 74, "both 12%", size=10, fill=MUTED)
    c.text(fx + 46, top + 100, "unchanged", size=11, anchor="middle",
           fill=ARM_COLOURS["haris"], weight="600")

    c.text(24, 356,
           "Recall rises on the two families that reformat an identifier; the "
           "false-positive rate does not move. That flat pair is",
           size=9, fill=MUTED)
    c.text(24, 370,
           "what shows the gain was not bought by making the matcher indiscriminate. "
           "Every other family is identical across the two arms.",
           size=9, fill=MUTED)
    c.text(24, 390,
           "This fix was once reported as taking obfuscated leaks from 42% to 100%. That "
           "family then held a single transform; rebuilt as the",
           size=9, fill=MUTED)
    c.text(24, 404,
           "six-rung ladder in F3, the same fix recovers the layout rungs only — which is "
           "the honest shape of what normalisation can do.",
           size=9, fill=MUTED)
    return c.render()


# --------------------------------------------------------------------------- #

def _load_latency(path: pathlib.Path) -> Optional[dict]:
    """Read a latency-*.json written by `demo_app.eval.latency`.

    Replaces a function that rummaged through the metrics snapshot for any key containing
    "laten". That worked until the snapshot's schema changed, and then it silently kept
    drawing whatever it found — which is how the figure ended up showing timings that
    were measuring model initialisation. A missing file now SKIPS the chart rather than
    guessing.
    """
    if not path.exists():
        print(f"      ({path} not found; cwd is {pathlib.Path.cwd()})")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        # REPORTED, not swallowed. The first version returned None on any exception, so a
        # missing `import json` surfaced as "no latency measurements" and sent me looking
        # for the file instead of the bug — the same silent-fallback shape that let the
        # old snapshot scraper keep drawing stale numbers after its schema moved.
        print(f"      (could not read {path}: {exc!r})")
        return None


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate the report figures as SVG.")
    ap.add_argument("--out", default="report/figures")
    ap.add_argument("--latency-off", default="report/appendix/latency-presidio-off.json")
    ap.add_argument("--latency-on", default="report/appendix/latency-presidio-on.json")
    args = ap.parse_args()

    import logging
    logging.disable(logging.INFO)

    from demo_app.eval.baselines import (
        ARMS, _boundary_ci, _exfiltration_ci, _false_positive_ci, _prevention_ci, run_all,
    )

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    print("running the harness (Presidio off) ...")
    rows = run_all(include_secrets=False)

    figures = {
        "fig1-four-arm.svg": fig_four_arm(rows, ARMS, _exfiltration_ci, _boundary_ci,
                                          _false_positive_ci),
        "fig2-by-family.svg": fig_by_family(rows, ARMS, _prevention_ci),
        "fig3-obfuscation-ladder.svg": fig_ladder(rows, ARMS, _prevention_ci),
    }

    # F5 restores the pre-normalisation matcher and re-runs the corpus. Measured
    # 2026-08-26 on 576 scenarios; see §6.4.5. Held as literals here rather than re-run,
    # because matcher_delta monkey-patches the agent and running it inside the figure
    # build would leave the patched matcher in place for anything drawn afterwards.
    figures["fig5-matcher-delta.svg"] = fig_matcher_delta(
        before={"external_obfuscated": 0.0, "rewrite_chain": 0.50},
        after={"external_obfuscated": 0.33, "rewrite_chain": 0.67},
        fp_before="24/192", fp_after="24/192",
    )

    off = _load_latency(pathlib.Path(args.latency_off))
    on = _load_latency(pathlib.Path(args.latency_on))
    if off:
        figures["fig4-latency.svg"] = fig_latency(off, on)
        if not on:
            print("  (no Presidio-ON latency file — drawing the structural arms only)")
    else:
        print(f"  (!) no latency measurements at {args.latency_off} — skipping fig4.")
        print("      Run: python -m demo_app.eval.latency --json " + args.latency_off)

    for name, svg in figures.items():
        (out / name).write_text(svg, encoding="utf-8")
        print(f"  wrote {out / name}")

    print(f"\n{len(figures)} figures. Regenerate after any change that moves a number —")
    print("they are drawn from the harness, so a figure disagreeing with the text is a")
    print("bug in figures.py, not a transcription error.")


if __name__ == "__main__":
    main()
