"""Print '<lost> <freshness_fail>' of a gateway run directory: PDUs sent and not delivered, and freshness failures.

usage: python3 -I lost_fresh.py <run_dir>
Reads all parts app_tx*.csv and app_rx*.csv (a replaced gateway leaves app_rx2.csv and so on); the driver's joined
*_all.csv files are skipped.
"""
import csv
import glob
import sys


def rows(d, pat):
    out = []
    for f in sorted(glob.glob(f"{d}/{pat}")):
        if f.endswith("_all.csv"):
            continue
        out += list(csv.DictReader(l for l in open(f) if not l.startswith("#")))
    return out


d = sys.argv[1]
tx, rx = rows(d, "app_tx*.csv"), rows(d, "app_rx*.csv")
print(len(tx) - sum(r["result"] == "ok" for r in rx), sum(r["result"] == "freshness_fail" for r in rx))
