#!/usr/bin/env python3
"""Assert the acceptance test's two conditions and write the proof artifact.

  (1) ATLAS integrated_count rises 0 -> N, and N equals the count of DISTINCT
      ATLAS techniques carrying >=1 shipped relation in crosswalk.csv.
  (2) Every other framework's included/integrated/relationship counts are unchanged.

Exit non-zero if either fails. Writes data/acceptance-result.json (the number the
essay and the email quote).
"""
import csv
import json
import sys
from pathlib import Path

PROJ = Path(__file__).resolve().parent.parent


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("base"); ap.add_argument("after")
    ap.add_argument("--expected", type=int, default=None,
                    help="expected ATLAS integrated count (default: derive from crosswalk.csv, the July run)")
    ap.add_argument("--out", default=str(PROJ / "data" / "acceptance-result.json"))
    args = ap.parse_args()
    base = json.load(open(args.base))
    after = json.load(open(args.after))
    b = {f["id"]: f for f in base["frameworks"]}
    a = {f["id"]: f for f in after["frameworks"]}

    expected = args.expected
    csv_path = PROJ / "crosswalk.csv"
    if expected is None and csv_path.exists():
        rows = list(csv.DictReader(open(csv_path)))
        expected = len({r["atlas_id"] for r in rows
                        if r.get("artifact_iri") and r.get("disposition") != "no-fit"})

    ok = others_ok = True
    print(f"{'framework':<20} {'included':<18} {'integrated':<18} coverage")
    for fid in b:
        fb, fa = b[fid], a.get(fid, {})
        incl = f"{fb['included_count']} -> {fa.get('included_count')}"
        integ = f"{fb['integrated_count']} -> {fa.get('integrated_count')}"
        cov = f"{fb['coverage_percent']}% -> {fa.get('coverage_percent')}%"
        flag = ""
        if fid == "atlas":
            if fa.get("integrated_count", 0) <= 0:
                flag, ok = "  !! ATLAS DID NOT MOVE OFF ZERO", False
            elif expected is not None and fa["integrated_count"] != expected:
                flag = f"  !! integrated {fa['integrated_count']} != crosswalk.csv expects {expected}"
                ok = False
            else:
                flag = "  <== the proof"
        else:
            for k in ("included_count", "integrated_count", "relationship_count"):
                if fb.get(k) != fa.get(k):
                    flag, ok, others_ok = f"  !! CHANGED {k}: {fb.get(k)} -> {fa.get(k)}", False, False
        print(f"{fid:<20} {incl:<18} {integ:<18} {cov}{flag}")

    result = {
        "atlas_integrated_before": b["atlas"]["integrated_count"],
        "atlas_integrated_after": a["atlas"]["integrated_count"],
        "atlas_included": a["atlas"]["included_count"],
        "atlas_coverage_percent_after": a["atlas"]["coverage_percent"],
        "atlas_relationship_count_after": a["atlas"]["relationship_count"],
        "expected": expected,
        "atlas_matches_expected": a["atlas"]["integrated_count"] == expected,
        "other_frameworks_unchanged": others_ok,
        "totals_before": base["totals"], "totals_after": after["totals"],
        "ontology": after.get("ontology"),
    }
    json.dump(result, open(args.out, "w"), indent=1)
    print("\nACCEPTANCE:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
