"""attack.csv: on-the-wire attack injection, receiver side."""
import numpy as np

from analysis import stats

STAGES = ("none", "framing", "freshness", "auth")
UNTIMED_ORACLE = "gateway_app_log"  # '# oracle=' of a file whose detect_ns is 0 by construction: the times are not measured


def analyse(cols, timed=True):
    """Per vector: n, delivered (reached the application), rejected (reject_stage != none), the
    rejection rate with its Wilson and its exact two-sided Clopper-Pearson 95% interval, counts
    per reject_stage, and describe() in microseconds of the time to detect (detect_ns: complete
    reception to the reject decision) over the rejected PDUs.

    'stages' repeats this per reject stage (framing, freshness, auth): how many of the vector's n
    PDUs were rejected there, that proportion with its Clopper-Pearson interval (a count of 0 still
    bounds the rate from above), and the time to detect at that stage.

    For 'benign': the false rejections (benign PDUs not delivered), their rate with the exact
    two-sided Clopper-Pearson 95% interval, and the ONE-sided 95% Clopper-Pearson upper bound.

    With timed=False (a file whose oracle records no decision time: detect_ns is 0 by construction)
    every detect_us is None: the zeros are not measurements."""
    delivered, stage = cols["delivered"] == "1", cols["reject_stage"]
    bad = np.flatnonzero(delivered & (stage != "none"))
    if bad.size:
        raise ValueError(f"data row {int(bad[0]) + 1}: delivered=1 with reject_stage={stage[bad[0]]}")
    out = []
    for v in dict.fromkeys(cols["vector"].tolist()):
        s = cols["vector"] == v
        rej = s & (stage != "none")
        n, k = int(s.sum()), int(rej.sum())
        t = stats.describe(cols["detect_ns"][rej] / 1e3) if timed else None
        r = {"vector": v, "n": n, "delivered": int((s & delivered).sum()), "rejected": k, "rejection_rate": k / n,
             "rejection_wilson95": list(stats.wilson_interval(k, n)),
             "rejection_cp95": list(stats.clopper_pearson_interval(k, n)),
             "by_stage": {st: int((s & (stage == st)).sum()) for st in STAGES}, "detect_us": t, "stages": []}
        for st in STAGES[1:]:
            at = s & (stage == st)
            c = int(at.sum())
            r["stages"].append({"stage": st, "count": c, "rate": c / n, "cp95": list(stats.clopper_pearson_interval(c, n)),
                                "detect_us": stats.describe(cols["detect_ns"][at] / 1e3) if timed else None})
        if v == "benign":
            r["false_rejections"] = n - r["delivered"]
            r["false_rejection_rate"] = r["false_rejections"] / n
            r["false_rejection_cp95"] = list(stats.clopper_pearson_interval(r["false_rejections"], n))
            r["false_rejection_upper95"] = stats.clopper_pearson_upper(r["false_rejections"], n)
        out.append(r)
    return out
