"""fig_survival.py <run dir> <analysis dir> <key prefix> <out.pdf> — the survival figure of the signing time for the
manuscript, drawn as the toolkit draws it (1 - ECDF as a step curve; a dashed line with the fitted ratio per
millisecond, anchored at the measured point at the start of the fit range), with a legend and axis text for print.
The curve is computed here from the raw file; the ratio and the fit range are the toolkit's keys of the run."""
import csv, os, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

run, ana, prefix, out = sys.argv[1:5]
K = {}
with open(os.path.join(ana, "numbers.csv"), newline="") as fh:
    for r in csv.DictReader(fh):
        K[r["key"]] = float(r["value"]) if r["value"] not in ("", None) else None
k = lambda name: K[f"{prefix}.crypto_ops.sign_p8.mldsa_sign.{name}"]
v = []
with open(os.path.join(run, "crypto_ops", "crypto_ops_sign_p8.csv")) as fh:
    cols = None
    for line in fh:
        if line.startswith("#") or not line.strip():
            continue
        f = line.rstrip("\n").split(",")
        if cols is None:
            cols = {c: i for i, c in enumerate(f)}; continue
        if f[cols["op"]] == "mldsa_sign" and int(f[cols["seq"]]) >= 1000:      # warm-up dropped, as everywhere
            v.append(int(f[cols["ns"]]))
x = np.sort(np.array(v, dtype=np.int64)) / 1e6                                  # milliseconds
assert len(x) == int(k("n")), (len(x), k("n"))                                  # the same calls as the toolkit's
surv = 1.0 - np.arange(1, len(x) + 1) / len(x)
lo, hi, ratio = int(k("tail_fit_from_ms")), int(k("tail_fit_to_ms")), k("tail_ratio_per_ms")
t = np.arange(lo, hi + 1)
anchor = np.count_nonzero(x > lo) / len(x)
fig, ax = plt.subplots(figsize=(5, 3.2))
ax.step(x[:-1], surv[:-1], where="post", label=f"signing calls ({len(x):,})")
ax.plot(t, anchor * ratio ** -(t - lo), color="black", linestyle="--", linewidth=1.0, zorder=3, label=f"fitted decay: factor {ratio:.3g} per ms ({lo} to {hi} ms)")
ax.set(yscale="log", xlabel="signing time (ms)", ylabel="share of calls that take longer")   # no symbol t: t is the tag length in the paper
ax.legend(fontsize=7)
fig.tight_layout(); fig.savefig(out); print("written", out, "| calls", len(x), "| ratio", ratio, "| range", lo, hi)
