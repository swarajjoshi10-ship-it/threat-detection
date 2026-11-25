"""Make the three README figures (docs/figures/*.png) from the saved reports and the LANL DB.

    python docs/make_figures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import duckdb
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "figures"
REPORTS = ROOT / "reports"

# validated default palette (light surface #fcfcfb), slots in fixed order
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "text.color": INK, "font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True,
    "axes.titlesize": 12, "axes.titleweight": "bold", "axes.titlelocation": "left",
})


def recall_by_detector():
    names = {"rules": "Rules baseline", "iforest": "Isolation Forest", "two_stage": "Two-stage (v2 best)",
             "iforest_v3": "Isolation Forest + host features", "host_fanout": "Host fan-out (v3, W=14)"}
    dev = json.loads((REPORTS / "hostrisk_dev_w14.json").read_text())["results"]
    post = json.loads((REPORTS / "hostrisk_posthoc_w14.json").read_text())["results"]
    keys = list(names)
    fig, ax = plt.subplots(figsize=(8, 4.2))
    h = 0.36
    for i, k in enumerate(keys):
        y = len(keys) - 1 - i
        for off, src, col in ((h / 2 + 0.01, dev, BLUE), (-h / 2 - 0.01, post, ORANGE)):
            v = src[k]["recall@50/day"] * 100
            ax.barh(y + off, v, height=h, color=col, edgecolor=SURFACE, linewidth=2)
            ax.text(v + 1, y + off, f"{v:.1f}%", va="center", fontsize=9, color=INK2)
    ax.set_yticks(range(len(keys)), [names[k] for k in reversed(keys)])
    ax.set_xlim(0, 100)
    ax.set_xlabel("Malicious user-days caught at 50 alerts per day (%)")
    ax.grid(axis="y", visible=False)
    ax.set_title("What works on days 8–14 mostly fails on days 15–29")
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=BLUE, label="Days 8–14 (validation)"),
                       Patch(color=ORANGE, label="Days 15–29 (holdout / post-hoc)")],
              loc="upper right", frameon=False)
    fig.tight_layout()
    fig.savefig(OUT / "recall_by_detector.png", dpi=160)


def attacker_host_fanout():
    from detections.rule import PARAMS, build
    con = duckdb.connect(":memory:")
    con.execute(f"ATTACH '{(ROOT / 'data' / 'lanl30.duckdb').as_posix()}' AS src (READ_ONLY)")
    con.execute("CREATE VIEW auth_events AS SELECT * FROM src.main.auth_events")
    con.execute("CREATE SCHEMA hostrisk")
    for t in ("pairs", "host_day_w14", "host_day_w28"):
        con.execute(f"CREATE VIEW hostrisk.{t} AS SELECT * FROM src.hostrisk.{t}")
    thr = build(con, **{k: PARAMS[k] for k in ("w", "min_new", "watch_days", "budget")})
    q = lambda s: con.execute(s).df()
    w14 = q("SELECT day, fanout FROM hostrisk.host_day_w14 WHERE src_comp='C17693' ORDER BY day")
    w28 = q("SELECT day, fanout FROM hostrisk.host_day_w28 WHERE src_comp='C17693' ORDER BY day")
    watch = q("SELECT day, n_suspect_users / (1.0 + n_baseline_users) AS fanout FROM detections.fanout_host_alerts "
              "WHERE src_comp='C17693' ORDER BY day")
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.axvspan(14.5, 29.5, color=GRID, alpha=0.45, linewidth=0)
    ax.text(15, 33.5, "days 15–29", color=INK2, fontsize=9)
    ax.axhline(thr, color=INK2, linewidth=1, linestyle=(0, (4, 3)))
    ax.text(0.3, thr + 0.6, f"rule threshold {thr:g}", color=INK2, fontsize=9)
    series = [(w14, BLUE, "14-day window (pre-registered)"), (w28, ORANGE, "28-day window"),
              (watch, AQUA, "14-day + watch list (frozen baseline)")]
    for df, col, label in series:
        ax.plot(df.day, df.fanout, color=col, linewidth=2, marker="o", markersize=4.5,
                markeredgecolor=SURFACE, markeredgewidth=1.5, label=label)
        last = df.iloc[-1]
        ax.annotate(f"{last.fanout:.2f}" if last.fanout < 1 else f"{last.fanout:.1f}", (last.day, last.fanout),
                    xytext=(6, 0), textcoords="offset points", va="center", fontsize=9, color=INK2)
    ax.set_xlim(0, 31.5)
    ax.set_ylim(0, 36)
    ax.set_xlabel("Day")
    ax.set_ylabel("Fan-out: new users / (1 + established)")
    ax.set_title("Attacker host C17693 ages into 'normal' unless its baseline is frozen")
    ax.text(0.3, 18.5, "all three coincide until day 14", color=INK2, fontsize=9)
    ax.legend(loc="upper left", frameon=False, bbox_to_anchor=(0, 0.93))
    fig.tight_layout()
    fig.savefig(OUT / "attacker_host_fanout.png", dpi=160)


def triage_faithfulness():
    runs = [("v2: model copies values\n(days 8–14, 350)", 0.0),
            ("v3 n1 pilot\n(20)", 0.0),
            ("v3 n2 pilot\n(20)", 55.0),
            ("v3 n2\n(days 8–14, 350)", 27.1)]
    v2 = json.loads((REPORTS / "triage" / "eval_evidence_lanl_v2__qwen2.5-7b__n2.json").read_text())
    runs[3] = (runs[3][0], round(v2["faithfulness"]["alerts_fully_faithful"] * 100, 1))
    fig, ax = plt.subplots(figsize=(8, 3.8))
    xs = range(len(runs))
    ax.bar(xs, [v for _, v in runs], width=0.55, color=BLUE, edgecolor=SURFACE, linewidth=2)
    for x, (_, v) in zip(xs, runs):
        ax.text(x, v + 2, f"{v:.1f}%" if v else "0%", ha="center", fontsize=9, color=INK2)
    ax.axhline(90, color=INK2, linewidth=1, linestyle=(0, (4, 3)))
    ax.text(len(runs) - 0.5, 92, "pre-registered target 90%", ha="right", color=INK2, fontsize=9)
    ax.set_xticks(list(xs), [n for n, _ in runs])
    ax.set_ylim(0, 100)
    ax.set_ylabel("Alerts fully faithful (%)")
    ax.grid(axis="x", visible=False)
    ax.set_title("LLM triage (qwen2.5 7B): no version reaches the faithfulness target")
    fig.tight_layout()
    fig.savefig(OUT / "triage_faithfulness.png", dpi=160)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(ROOT))
    OUT.mkdir(parents=True, exist_ok=True)
    recall_by_detector()
    attacker_host_fanout()
    triage_faithfulness()
    print("wrote", *sorted(p.name for p in OUT.glob("*.png")))
