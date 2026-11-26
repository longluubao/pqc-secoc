"""Standalone vs Csm-integrated overhead: overhead_paired.csv (paired) and legacy phase_compare.csv (unpaired)."""
from pathlib import Path

import numpy as np

from analysis import stats

MARGIN_FILE = "equivalence_margin.txt"
MIN_LAUNCHES = 5  # fewer launches than this give no across-launch verdict


def read_margin(run_dir, marker=None):
    """Relative equivalence margin (e.g. 0.01 for +/-1%) from <run_dir>/equivalence_margin.txt.
    The margin must be fixed before the data is seen, so a missing or malformed file is an error,
    and so is a file whose comment calls it a placeholder, unless the run directory is marked
    DRY_RUN or PILOT (`marker`), where nothing is a result anyway."""
    path = Path(run_dir) / MARGIN_FILE
    if not path.is_file():
        raise FileNotFoundError(f"{path} is missing: write the pre-registered relative equivalence margin "
                                f"(one number such as 0.01) there before analysing overhead_paired.csv")
    text = path.read_text().splitlines()
    if marker is None and any("placeholder" in s.lower() for s in text if s.lstrip().startswith("#")):
        raise ValueError(f"{path}: the file calls itself a placeholder, and the run directory has no DRY_RUN or PILOT "
                         "marker; write the pre-registered margin, or mark the directory")
    lines = [s for s in map(str.strip, text) if s and not s.startswith("#")]
    try:
        (margin,) = map(float, lines)
    except ValueError:
        raise ValueError(f"{path}: expected exactly one number such as 0.01, got {lines!r}") from None
    if not 0 < margin < 1:
        raise ValueError(f"{path}: margin must be a relative value in (0, 1), got {margin}")
    return margin


def _us(v):
    return None if v is None else v / 1e3


def _hl(est, lo, hi):
    return {"estimate_us": _us(est), "ci95_us": [_us(lo), _us(hi)]}


def analyse_paired(cols, margin, warmup, noise_floor=False):
    """Per op, on pairs with seq >= warmup (differences are csm - standalone):
    median of paired differences and of paired ratios csm/standalone; paired Hodges-Lehmann estimate
    (median of Walsh averages) with 95% CI; Wilcoxon signed-rank p; TOST on paired log-ratios against
    `margin` (geometric mean of the ratios); Cliff's delta (unpaired dominance between the two
    columns); and an order-effect check comparing the differences of AB pairs (A = standalone ran
    first) with those of BA pairs (two-sample Hodges-Lehmann shift BA - AB and Mann-Whitney p).

    Every interval and test here treats the pairs as independent draws. That holds within one process
    launch only: identical launches differ by more than these intervals (a per-launch layout effect),
    so the result is optimistic. across_launches() gives the interval that includes it.

    `noise_floor`: the file is an A/A run (the csm_ns column is a second standalone call). The
    geometric-mean ratio and its interval are reported, but it is not judged against the margin:
    margin, p and equivalent are None."""
    out = []
    for op in dict.fromkeys(cols["op"].tolist()):
        sel = cols["op"] == op
        keep = sel & (cols["seq"] >= warmup)
        a, b, order = cols["standalone_ns"][keep], cols["csm_ns"][keep], cols["order"][keep]
        if a.size == 0:
            raise ValueError(f"op {op}: no pairs left after dropping seq < {warmup}")
        d = b - a
        r = {"op": op, "n_pairs": int(a.size), "n_warmup_dropped": int(sel.sum() - a.size),
             "median_standalone_us": float(np.median(a)) / 1e3, "median_csm_us": float(np.median(b)) / 1e3,
             "median_diff_us": float(np.median(d)) / 1e3, "median_ratio": float(np.median(b / a)),
             "hl_paired": _hl(*stats.hodges_lehmann_paired(d)), "wilcoxon_p": stats.wilcoxon_p(a, b),
             # a noise-floor file is not judged: the margin enters only p and 'equivalent', which are dropped below,
             # so any margin serves there (an A/A run directory has no margin file)
             "tost_paired_log": stats.tost_log_paired(a, b, 0.5 if noise_floor else margin),
             "cliffs_delta": stats.mann_whitney(a, b)[1]}
        if noise_floor:
            r["tost_paired_log"].update(margin=None, p=None, equivalent=None)
        ab, ba = d[order == "AB"], d[order == "BA"]
        oe = {"n_AB": int(ab.size), "n_BA": int(ba.size)}
        if ab.size and ba.size:
            oe.update(median_diff_AB_us=float(np.median(ab)) / 1e3, median_diff_BA_us=float(np.median(ba)) / 1e3,
                      hl_shift_BA_minus_AB=_hl(*stats.hodges_lehmann_two_sample(ab, ba)),
                      mann_whitney_p=stats.mann_whitney(ab, ba)[0])
        r["order_effect"] = oe
        out.append(r)
    return out


def _spread(x):
    """Mean, sd, min, max and the Student-t 95% and 90% intervals of the mean of launch-level values."""
    x = np.asarray(x, dtype=float)
    mean, lo95, hi95 = stats.mean_ci(x, 0.95)
    _, lo90, hi90 = stats.mean_ci(x, 0.90)
    return {"mean": mean, "sd": float(x.std(ddof=1)) if x.size > 1 else None, "min": float(x.min()), "max": float(x.max()),
            "t95": [lo95, hi95], "t90": [lo90, hi90]}


def across_launches(per_launch, margin, noise_floor=False):
    """The paired comparison with the process launch as the unit of replication.

    per_launch: [(launch id, analyse_paired() result of that launch), ...] of one launch set.
    Per op, over one value per launch: the paired Hodges-Lehmann estimates (us) and the
    geometric-mean ratios csm/standalone, each with mean, sd, min, max and Student-t 95% and 90%
    intervals of the mean (ratios are averaged on the log scale, so 'mean' is their geometric mean),
    and TOST of the launch-level log-ratios against the margin with n = number of launches.

    This is the headline: its interval contains the launch-to-launch variation that the
    within-launch interval of analyse_paired() leaves out. It assumes the launches are independent
    and roughly normal on the log-ratio scale. With fewer than MIN_LAUNCHES launches, or for a
    noise-floor (A/A) set, there is no verdict: 'tost' is None and 'verdict' says why.
    """
    out = []
    for op in dict.fromkeys(o["op"] for _, ops in per_launch for o in ops):
        rows = [(launch, o) for launch, ops in per_launch for o in ops if o["op"] == op]
        logs = _spread(np.log([o["tost_paired_log"]["gm_ratio"] for _, o in rows]))
        ratio = {k: (None if v is None else float(np.exp(v))) for k, v in logs.items() if k not in ("sd", "t95", "t90")}
        ratio.update(log_sd=logs["sd"], t95=[None if v is None else float(np.exp(v)) for v in logs["t95"]],
                     t90=[None if v is None else float(np.exp(v)) for v in logs["t90"]])
        r = {"op": op, "n_launches": len(rows), "launches": [launch for launch, _ in rows],
             "pairs_per_launch": [o["n_pairs"] for _, o in rows],
             "hl_us": _spread([o["hl_paired"]["estimate_us"] for _, o in rows]), "gm_ratio": ratio, "tost": None}
        if noise_floor:
            r["verdict"] = "noise floor: not judged against the margin"
        elif len(rows) < MIN_LAUNCHES:
            r["verdict"] = f"no verdict: {len(rows)} launch(es), fewer than {MIN_LAUNCHES}"
        else:
            r["tost"] = stats.tost_log_values(np.log([o["tost_paired_log"]["gm_ratio"] for _, o in rows]), margin)
            r["verdict"] = "equivalent within the margin" if r["tost"]["equivalent"] else "equivalence not shown"
        out.append(r)
    return out


# what every figure of the legacy comparison has to say about itself
SEQUENTIAL = ("the two phases ran one after the other in one run (not paired, not interleaved), so a change of the system "
              "between them is part of the difference")
POST_HOC = "the margin was chosen after the data had been seen"
WITHIN = "it sees dependence within a phase only: a drift between the two phases is confounded with the comparison"


def analyse_unpaired(cols, warmup, margins, block_len=None, n_boot=None, rng=None):
    """Legacy phase_compare.csv: two independent samples per op (arm 'standalone' and 'csm'), each
    with seq < warmup dropped and taken in the order of seq. Medians, Mann-Whitney p, two-sample
    Hodges-Lehmann shift csm - standalone with 95% CI, Cliff's delta, and a two-sample TOST on
    log-times per margin. The margins here were chosen after the data was seen, so these TOSTs are
    post hoc, and the two samples are phases measured one after the other (SEQUENTIAL).

    With `rng` (and block_len, n_boot): the lag-1 autocorrelation of each phase and the moving-block
    bootstrap 90% interval of median csm / median standalone - 1 (stats.block_bootstrap_ratio_of_medians_ci);
    both see dependence within a phase only (WITHIN)."""
    out = []
    for op in dict.fromkeys(cols["op"].tolist()):
        arm = {}
        for name in ("standalone", "csm"):
            sel = np.flatnonzero((cols["op"] == op) & (cols["arm"] == name) & (cols["seq"] >= warmup))
            arm[name] = cols["ns"][sel[np.argsort(cols["seq"][sel], kind="stable")]]
            if arm[name].size == 0:
                raise ValueError(f"op {op}: no {name} samples left after dropping seq < {warmup}")
        a, b = arm["standalone"], arm["csm"]
        p, delta = stats.mann_whitney(a, b)
        ma, mb = float(np.median(a)), float(np.median(b))
        out.append({"op": op, "n_standalone": int(a.size), "n_csm": int(b.size), "warmup": warmup,
                    "median_standalone_us": ma / 1e3, "median_csm_us": mb / 1e3, "median_rel_diff": mb / ma - 1,
                    "mann_whitney_p": p, "hl_shift": _hl(*stats.hodges_lehmann_two_sample(a, b)),
                    "cliffs_delta": delta,
                    "tost_log_post_hoc": [stats.tost_log_two_sample(a, b, m) for m in margins]})
        if rng is not None:
            lo, hi = stats.block_bootstrap_ratio_of_medians_ci(a, b, block_len, n_boot, 0.90, rng)
            out[-1].update(lag1_standalone=stats.lag1_autocorr(a), lag1_csm=stats.lag1_autocorr(b),
                           bootstrap={"median_rel_diff_ci90": [float(lo) - 1, float(hi) - 1], "block_len": block_len,
                                      "n_boot": n_boot})
    return out
