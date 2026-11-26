"""Trace-driven queue model of periodic authenticated streams, to set next to measured miss ratios.

    python3 -m analysis.simulate <crypto_ops.csv | tx_perf_10k.csv> --op mldsa_sign --period-ms 10 --streams 3
        [--cores 1] [--deadline-ms 10]
"""
import argparse
import heapq
import json
import sys
from pathlib import Path

if __package__ in (None, ""):  # run by path under python3 -I, which keeps the script directory off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis import crypto_ops, csvio  # noqa: E402  (first: the package makes numpy importable under -I)

import numpy as np  # noqa: E402


def miss_ratio(service, period, streams, cores, jobs, rng, offsets=None, deadline=None):
    """Fraction of jobs whose response time exceeds `deadline` (strict; the period if not given) in
    one simulated run.

    Model: `streams` periodic sources with a common period and relative deadline; one global
    non-preemptive FIFO queue in release order served by `cores` identical servers; each job's
    service time drawn with replacement from the measured sample `service`. Service times are
    therefore i.i.d.: serial correlation in the measurement, and any cost that is not in
    `service`, are not modelled. `offsets` are the per-stream release offsets: None draws them
    independently uniform on [0, period), zeros are the synchronous (critical-instant) case.
    `service`, `period`, `offsets` and `deadline` share one unit.
    """
    deadline = period if deadline is None else deadline
    per_stream = -(-jobs // streams)
    offsets = rng.uniform(0, period, streams) if offsets is None else np.asarray(offsets, dtype=float)
    if offsets.shape != (streams,):
        raise ValueError(f"need one offset per stream ({streams}), got shape {offsets.shape}")
    release = np.sort((offsets[:, None] + period * np.arange(per_stream)).ravel(), kind="stable")[:jobs]
    free = [0.0] * cores  # heap of the instants at which each server becomes idle
    misses = 0
    for r, c in zip(release.tolist(), rng.choice(service, size=release.size).tolist()):
        finish = max(r, free[0]) + c
        heapq.heapreplace(free, finish)
        misses += finish - r > deadline
    return misses / release.size


def model(service, period, streams, cores, *, rng, deadline=None, draws=20, fixed_runs=3, jobs=200_000,
          measured_offsets=None, measured_jobs=None):
    """Miss ratio of the model in miss_ratio(): mean, minimum and maximum over `draws` independent
    random-offset draws; the mean over `fixed_runs` synchronous-release runs (the critical instant);
    and, if `measured_offsets` is given, the mean over `fixed_runs` runs with exactly those offsets
    and `measured_jobs` jobs, which is the case to compare with the measurement they came from.
    At utilisation near or above 1 the backlog grows with run length, so a miss ratio is only
    comparable between runs of the same number of jobs; the other two cases use `jobs`.
    utilisation = streams * mean(service) / (cores * period)."""
    service = np.asarray(service, dtype=float)

    def mean_of(offsets, runs, n_jobs):
        return float(np.mean([miss_ratio(service, period, streams, cores, n_jobs, rng, offsets, deadline)
                              for _ in range(runs)]))

    rnd = [miss_ratio(service, period, streams, cores, jobs, rng, None, deadline) for _ in range(draws)]
    out = {"utilisation": float(streams * service.mean() / (cores * period)), "jobs_per_run": jobs,
           "random_offsets": {"draws": draws, "mean": float(np.mean(rnd)), "min": min(rnd), "max": max(rnd)},
           "synchronous": {"runs": fixed_runs, "mean": mean_of(np.zeros(streams), fixed_runs, jobs)}}
    if measured_offsets is not None:
        n_jobs = measured_jobs or jobs
        out["measured_offsets"] = {"runs": fixed_runs, "jobs_per_run": n_jobs,
                                   "mean": mean_of(measured_offsets, fixed_runs, n_jobs)}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Modelled deadline-miss ratio from a measured service-time sample.")
    ap.add_argument("csv", type=Path, help="crypto_ops.csv, or the legacy tx_perf_10k.csv")
    ap.add_argument("--op", default="mldsa_sign", help="op whose times are the service sample ('sign' for the legacy file)")
    ap.add_argument("--period-ms", type=float, required=True)
    ap.add_argument("--streams", type=int, required=True)
    ap.add_argument("--cores", type=int, default=1)
    ap.add_argument("--deadline-ms", type=float, help="relative deadline (default: the period)")
    ap.add_argument("--warmup", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=20261122)
    a = ap.parse_args(argv)
    kind, _, cols = csvio.load(a.csv)
    if kind != "crypto_ops":
        ap.error(f"{a.csv} is a {kind} file, need crypto_ops")
    service = crypto_ops.samples(cols, a.op, a.warmup)
    if service.size == 0:
        ap.error(f"no samples of op {a.op!r} after warm-up")
    deadline_ms = a.period_ms if a.deadline_ms is None else a.deadline_ms
    res = model(service, a.period_ms * 1e6, a.streams, a.cores, deadline=deadline_ms * 1e6, rng=np.random.default_rng(a.seed))
    print(json.dumps({"source": str(a.csv), "op": a.op, "n_service": int(service.size), "period_ms": a.period_ms,
                      "deadline_ms": deadline_ms, "streams": a.streams, "cores": a.cores, "seed": a.seed, **res}, indent=1))


if __name__ == "__main__":
    main()
