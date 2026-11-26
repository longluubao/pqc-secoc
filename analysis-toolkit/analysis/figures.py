"""Optional PDF figures. Needs matplotlib; make_tables skips this module when it is not installed.

"""
import numpy as np


NAMES = ("sign_tail_ecdf.pdf", "sign_tail_survival.pdf", "sign_attrib_cpu_vs_rounds.pdf", "sign_attrib_cpu_vs_rounds_paper.pdf",
         "periodic_response_ecdf.pdf", "throughput_delivered_vs_offered.pdf", "miss_ratio_vs_streams.pdf")
PAPER_LINE_MS = 10  # the horizontal line of the paper form of the rounds figure


def _ecdf(x, body_points=2000):
    """Sorted values and ECDF heights. The lowest 99% is thinned to about body_points points and the
    top 1% is kept whole, so a million-sample tail plot stays a small vector file."""
    x = np.sort(np.asarray(x, dtype=float))
    f = np.arange(1, x.size + 1) / x.size
    cut = int(0.99 * x.size)
    keep = np.r_[np.arange(0, cut, max(1, cut // body_points)), np.arange(cut, x.size)]
    return x[keep], f[keep]


def make_all(out_dir, data, summary, thresholds_ms, banner=None):
    """Write the figures that the available data allows and return the list of file names. `banner`
    (for example 'DRY RUN: not a result') is stamped in red across every figure.

    data: {"sign": [(label, times_us)], "response": [(label, response_us of finished jobs, deadline_us)],
    "tail": [(label, times_us, crypto_ops.tail() fit or None)],
    "attrib": [(label, rounds, cpu_us, sign_attrib fit)] for counting runs};
    summary: the make_tables results dict (throughput steps and periodic miss ratios).
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    written = []

    def save(fig, name):
        if banner:
            fig.text(0.5, 0.5, banner, color="red", alpha=0.45, fontsize=16, weight="bold", ha="center", va="center")
        fig.tight_layout()
        fig.savefig(out_dir / name)
        plt.close(fig)
        written.append(name)

    if data["sign"]:  # tail of the signing-time distribution: 1 - ECDF on a log axis, deadline markers
        fig, ax = plt.subplots(figsize=(5, 3.2))
        for label, x in data["sign"]:
            xs, f = _ecdf(x)
            ax.step(xs[:-1] / 1e3, 1 - f[:-1], where="post", label=label)
        for d in thresholds_ms:
            ax.axvline(d, color="0.5", linestyle=":", linewidth=0.8)
        ax.set(yscale="log", xlabel="signing time t (ms)", ylabel="P(time > t)")
        ax.legend(fontsize=6)
        save(fig, "sign_tail_ecdf.pdf")

    if data.get("tail"):  # survival function of the long signing series with the fitted geometric decay
        fig, ax = plt.subplots(figsize=(5, 3.2))
        for label, x, fit in data["tail"]:
            xs, f = _ecdf(x)
            line, = ax.step(xs[:-1] / 1e3, 1 - f[:-1], where="post", label=label)
            if fit:
                # the fit is on 1-ms bin counts; the line shows its slope, anchored at the measured point at from_ms
                t = np.arange(fit["from_ms"], fit["to_ms"] + 1)
                anchor = np.count_nonzero(np.asarray(x) > 1e3 * fit["from_ms"]) / len(x)
                # black and on top: in the curve's own colour the line would lie hidden on the curve it fits
                ax.plot(t, anchor * fit["ratio_per_ms"] ** -(t - fit["from_ms"]), color="black", linestyle="--", linewidth=1.0,
                        zorder=3, label=f"fit {fit['from_ms']}-{fit['to_ms']} ms: count / {fit['ratio_per_ms']:.3g} per ms")
        ax.set(yscale="log", xlabel="signing time t (ms)", ylabel="fraction of samples above t")
        ax.legend(fontsize=6)
        save(fig, "sign_tail_survival.pdf")

    # processor time against rounds: per number of rounds the range and the mean, and the fitted line. Twice: the working
    # form names the file in the legend; the paper form does not (with one file) and has a thin line at PAPER_LINE_MS
    for paper in ((False, True) if data.get("attrib") else ()):
        fig, ax = plt.subplots(figsize=(5, 3.2))
        for label, rounds, cpu, fit in data["attrib"]:
            ks = np.unique(rounds)
            groups = [np.asarray(cpu)[rounds == k] / 1e3 for k in ks]
            ax.vlines(ks, [g.min() for g in groups], [g.max() for g in groups], linewidth=0.8, color="0.6")
            series = "mean, minimum to maximum" if paper and len(data["attrib"]) == 1 else \
                f"{label}: mean, minimum to maximum" if paper else f"{label}: mean, min to max"
            ax.plot(ks, [g.mean() for g in groups], linestyle="none", marker="o", markersize=2.5, label=series)
            ax.plot(ks, (fit["cpu_intercept_us"] + fit["cpu_per_round_us"] * ks) / 1e3, color="black", linestyle="--", linewidth=1.0,
                    zorder=3, label=f"least squares: {fit['cpu_intercept_us']:.0f} + {fit['cpu_per_round_us']:.0f} µs per round")
        if paper:
            ax.axhline(PAPER_LINE_MS, color="0.3", linewidth=0.5, label=f"{PAPER_LINE_MS} ms")
        ax.set(xlabel="rounds", ylabel="processor time (ms)")
        ax.legend(fontsize=6)
        save(fig, "sign_attrib_cpu_vs_rounds_paper.pdf" if paper else "sign_attrib_cpu_vs_rounds.pdf")

    if data["response"]:
        fig, ax = plt.subplots(figsize=(5, 3.2))
        for label, x, deadline_us in data["response"]:
            if not len(x):
                continue
            xs, f = _ecdf(x)
            line, = ax.step(xs / 1e3, f, where="post", label=label)
            ax.axvline(deadline_us / 1e3, color=line.get_color(), linestyle=":", linewidth=0.8)
        ax.set(xscale="log", xlabel="response time (ms); dotted: deadline", ylabel="ECDF")
        ax.legend(fontsize=6)
        save(fig, "periodic_response_ecdf.pdf")

    if summary.get("throughput"):
        fig, ax = plt.subplots(figsize=(4, 3.2))
        top = 0.0
        for t in summary["throughput"]:
            steps = [s for s in t["saturation"]["steps"] if s["delivered_pps"] is not None]
            ax.plot([s["offered_pps"] for s in steps], [s["delivered_pps"] for s in steps], marker="o",
                    label=f"{t['source']}, {t['profile']}, {t['cores']} core(s)")
            top = max([top] + [s["offered_pps"] for s in steps])
        ax.plot([0, top], [0, top], color="0.5", linestyle=":", linewidth=0.8)
        ax.set(xlabel="offered rate (PDU/s)", ylabel="delivered rate (PDU/s)")
        ax.legend(fontsize=6)
        save(fig, "throughput_delivered_vs_offered.pdf")

    if summary.get("periodic"):
        groups = {}
        for p in summary["periodic"]:
            key = f"{p['period_us'] / 1e3:g} ms, {p['profile']}, {p['scheduler']}, {p['cores']} core(s)"
            groups.setdefault(key, []).append(p)
        fig, ax = plt.subplots(figsize=(5, 3.2))
        for key, ps in groups.items():
            ps = sorted(ps, key=lambda p: p["streams"])
            line, = ax.plot([p["streams"] for p in ps], [p["miss_ratio"] for p in ps], marker="o", label=key)
            if all("model" in p for p in ps):
                ax.plot([p["streams"] for p in ps], [p["model"]["random_offsets"]["mean"] for p in ps],
                        color=line.get_color(), linestyle="--", marker="x")
        ax.set(xlabel="streams", ylabel="deadline-miss ratio (dashed: model)")
        ax.set_yscale("symlog", linthresh=1e-5)
        ax.legend(fontsize=6)
        save(fig, "miss_ratio_vs_streams.pdf")
    return written
