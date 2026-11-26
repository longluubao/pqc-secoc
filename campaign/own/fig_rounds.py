"""fig_rounds.py <run dir> <analysis dir> <key prefix> <out.pdf> — processor time of a signing call against its number
of rounds of the rejection loop, drawn as the toolkit draws it (per number of rounds the range and the mean, the
least-squares line of the toolkit's keys, a thin line at 10 ms), with a legend for print. The points are computed here
from the raw file of the instrumented run; slope and intercept are the toolkit's keys of that run."""
import csv, os, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

run, ana, prefix, out = sys.argv[1:5]
K = {}
with open(os.path.join(ana, "numbers.csv"), newline="") as fh:
    for r in csv.DictReader(fh):
        try:
            K[r["key"]] = float(r["value"])
        except ValueError:
            pass
k = lambda name: K[f"{prefix}.crypto_attrib.sign_attrib_p8.{name}"]
smin, step = int(k("header.shake_calls_min")), int(k("header.shake_calls_step"))
rounds, cpu = [], []
with open(os.path.join(run, "crypto_attrib", "sign_attrib_p8.csv")) as fh:
    cols = None
    for line in fh:
        if line.startswith("#") or not line.strip():
            continue
        f = line.rstrip("\n").split(",")
        if cols is None:
            cols = {c: i for i, c in enumerate(f)}; continue
        if int(f[cols["seq"]]) >= 1000:                       # warm-up dropped, as everywhere
            q, rem = divmod(int(f[cols["shake_calls"]]) - smin, step)
            assert rem == 0, f
            rounds.append(q + 1); cpu.append(int(f[cols["cpu_ns"]]) / 1e6)      # milliseconds
rounds, cpu = np.array(rounds), np.array(cpu)
assert len(rounds) == int(k("n")), (len(rounds), k("n"))      # the same calls as the toolkit's
assert rounds.max() == int(k("rounds_max")), rounds.max()
ks = np.unique(rounds)
groups = [cpu[rounds == r] for r in ks]
slope, icpt = k("cpu_per_round_us"), k("cpu_intercept_us")
fig, ax = plt.subplots(figsize=(5, 3.2))
ax.vlines(ks, [g.min() for g in groups], [g.max() for g in groups], linewidth=0.8, color="0.6")
ax.plot(ks, [g.mean() for g in groups], linestyle="none", marker="o", markersize=2.5, label="mean, minimum to maximum")
ax.plot(ks, (icpt + slope * ks) / 1e3, color="black", linestyle="--", linewidth=1.0, zorder=3, label=f"least squares: {slope:.0f} µs per round + {icpt:.0f} µs")
ax.axhline(10, color="0.3", linewidth=0.5, label="10 ms")
ax.set(xlabel="rounds of the rejection loop", ylabel="processor time (ms)")
ax.legend(fontsize=7)
fig.tight_layout(); fig.savefig(out); print("written", out, "| calls", len(rounds), "| rounds up to", rounds.max(), "| slope", slope, "| intercept", icpt)
