#!/usr/bin/env python3
"""Apply the 2026-11 rebaseline verdicts and HARD-GATE every surviving row against develop.

Precedence for queued (core+annex) rows: author override > Opus V3 > Sonnet adjudicator.
Precedence for new v2026.10 rows: Opus V1/V2 verdict on the gated mapper row.
Every final row must pass: IRI in the develop artifact index, verb in the develop verb tree, and
evidence quote a verbatim substring of the definition it will be judged against (develop text for
queued rows, v2026.10 text for new rows). A failure is fatal; nothing is written.

Outputs (proposals pending upstream review; the canonical crosswalk.csv / annex CSV are NOT modified):
  crosswalk-rebaseline-2026-11.csv   queued rows with old -> final mapping, verdict, reason
  crosswalk-annex-v2026.10.csv       new-technique rows (pending ATLAS ingest; no IRIs on develop)
  work/rebaseline/rebaseline-final.json  everything, plus re-derived counts
"""
import csv
import glob
import json
import re
from collections import Counter
from pathlib import Path

PROJ = Path(__file__).resolve().parent.parent
RB = PROJ / "work" / "rebaseline"
DD = PROJ / "data" / "develop-2026-11"

SUCCESSOR = {"AML.T0019": "AML.T0115.000", "AML.T0058": "AML.T0115.001", "AML.T0104": "AML.T0115.002",
             "AML.T0024.000": "AML.T0137.000", "AML.T0024.001": "AML.T0137.002",
             "AML.T0024.002": "AML.T0005.001 (inferred)", "AML.T0056": "AML.T0085.003",
             "AML.T0057": "AML.T0085.002"}

# Author overrides on NEW rows: supply evidence where a verifier revision left none.
NEW_QUOTES = {"AML.T0122#a0": "cause the service to make network requests"}

# Author overrides (reasoned in REBASELINE-2026-11.md), applied last.
OVERRIDES = {
    "R020": {"verdict": "revise", "verb": "d3f:may-create", "artifact_iri": "d3f:DomainRegistration",
             "evidence_quote": "Infrastructure solutions include physical or cloud servers, domains, mobile devices, and third-party web services",
             "reason": "#616 record-not-identifier; domains are one option among several for the parent, so may-create (child T0008.002 carries the definite creates)"},
}


def norm(s):
    return re.sub(r"\s+", " ", s or "").strip()


def main():
    arts = {a["iri"]: a["label"] for a in json.load(open(DD / "artifact_index.json"))["artifacts"]}
    verbs = set(json.load(open(DD / "verb_tree.json"))["verbs"])
    errors = []

    # ---------- queued rows ----------
    inp, tech = {}, {}
    for f in sorted(RB.glob("adj-*.input.json")):
        for t in json.load(open(f))["techniques"]:
            tech[t["atlas_id"]] = t
            for r in t["rows"]:
                inp[r["row_id"]] = (t["atlas_id"], r)
    adj = {r["row_id"]: r for f in sorted(RB.glob("adj-*.output.json"))
           for t in json.load(open(f))["techniques"] for r in t["rows"]}
    v3 = {r["row_id"]: r for r in json.load(open(RB / "verify-V3.output.json"))["rows"]}
    queued = []
    for rid, (tid, r) in sorted(inp.items()):
        a = adj[rid]
        verdict, verb, iri, quote, reason, src = a["verdict"], r["verb"], r["artifact_iri"], r["evidence_quote"], a["reason"], "adjudicator(sonnet)"
        if verdict == "revise":
            verb = a.get("new_verb") or verb
            iri = a.get("new_artifact_iri") or iri
            quote = a.get("new_evidence_quote") or quote
        if rid in v3:
            x = v3[rid]
            src = "verify(opus)" if x.get("agree_with_adjudicator") else "verify(opus) override"
            verdict = x["final_verdict"]
            verb = x.get("final_verb") or r["verb"]
            iri = x.get("final_artifact_iri") or r["artifact_iri"]
            quote = x.get("final_evidence_quote") or r["evidence_quote"]
            reason = x["reason"]
        if rid in OVERRIDES:
            o = OVERRIDES[rid]
            verdict, verb, iri, quote, reason, src = (o["verdict"], o["verb"], o["artifact_iri"],
                                                      o["evidence_quote"], o["reason"], "author")
        t = tech[tid]
        if verdict != "retire":
            ddef = norm(t["definition_develop"])
            if iri not in arts:
                errors.append(f"{rid} {tid}: IRI {iri} not on develop")
            if verb not in verbs:
                errors.append(f"{rid} {tid}: verb {verb} not on develop")
            inherited_unchanged = r["disposition"] == "attack-inherited" and (verb, iri) == (r["verb"], r["artifact_iri"])
            if not inherited_unchanged and (not norm(quote) or norm(quote) not in ddef):
                errors.append(f"{rid} {tid}: quote not verbatim in develop definition")
        survives = None
        latest = norm(t.get("definition_latest"))
        if verdict != "retire" and latest:
            survives = norm(quote) in latest
        changed = (verb, iri) != (r["verb"], r["artifact_iri"]) or norm(quote) != norm(r["evidence_quote"])
        if verdict == "revise" and not changed:
            verdict = "keep"  # a "revise" that changes nothing is a keep
        queued.append({"row_id": rid, "atlas_id": tid, "label": t["label"], "wave": t["wave"],
                       "open_pr": t["open_pr"], "old_verb": r["verb"], "old_artifact": r["artifact_iri"],
                       "verdict": verdict, "verb": verb, "artifact_iri": iri,
                       "artifact_label": arts.get(iri, ""), "evidence_quote": quote,
                       "quote_changed": norm(quote) != norm(r["evidence_quote"]),
                       "removed_in_latest": t.get("latest_id") != tid,
                       "successor": SUCCESSOR.get(tid), "quote_survives_latest": survives,
                       "decided_by": src, "reason": reason})

    # ---------- new v2026.10 rows ----------
    mem = {m["atlas_id"]: m for m in json.load(open(DD / "atlas_members.json"))["members"]}
    vin = {}
    for u in ("V1", "V2"):
        for t in json.load(open(RB / f"verify-{u}.input.json"))["techniques"]:
            for r in t["rows"]:
                vin[r["row_id"]] = (t["atlas_id"], r)
    vout = {r["row_id"]: r for u in ("V1", "V2") for r in json.load(open(RB / f"verify-{u}.output.json"))["rows"]}
    vtech = {t["atlas_id"]: t for u in ("V1", "V2") for t in json.load(open(RB / f"verify-{u}.output.json"))["techniques"]}
    vprops = {t["atlas_id"]: t for u in ("V1", "V2") for t in json.load(open(RB / f"verify-{u}.input.json"))["techniques"]}
    new = []
    for rid, (tid, r) in sorted(vin.items()):
        v = vout[rid]
        verdict = {"uphold": "keep", "revise": "revise", "kill": "kill"}[v["verdict"]]
        verb = v.get("new_verb") or r["verb"]
        iri = v.get("new_artifact_iri") or r["artifact_iri"]
        quote = v.get("new_evidence_quote") or r.get("evidence_quote") or NEW_QUOTES.get(rid, "")
        kind = r["kind"]
        seed_pairs = {(vb, a["iri"]) for s_ in json.load(open(DD / "attack_seed.json"))["seeds"]
                      if s_["atlas_id"] == tid for a in s_["artifacts"] for vb in a["verbs"]}
        if kind == "attack_inherited" and (verb, iri) not in seed_pairs:
            kind = "mapping (revised from seed)"  # no longer an inherited pair: needs its own evidence
        if verdict != "kill":
            if iri not in arts:
                errors.append(f"new {rid}: IRI {iri} not on develop")
            if verb not in verbs:
                errors.append(f"new {rid}: verb {verb} not on develop")
            if kind != "attack_inherited" and (not norm(quote) or norm(quote) not in norm(mem[tid]["definition"])):
                errors.append(f"new {rid}: quote not verbatim in v2026.10 definition")
        new.append({"row_id": rid, "atlas_id": tid, "label": mem[tid]["label"], "kind": kind,
                    "mapper_verb": r["verb"], "mapper_artifact": r["artifact_iri"], "verdict": verdict,
                    "verb": verb, "artifact_iri": iri, "artifact_label": arts.get(iri, ""),
                    "evidence_quote": quote if kind != "attack_inherited" else "",
                    "reason": v["reason"]})

    if errors:
        raise SystemExit("GATE FAIL:\n  " + "\n  ".join(errors))

    # ---------- counts (re-derived here, never copied from agent replies) ----------
    q_tech_alive = {x["atlas_id"] for x in queued if x["verdict"] != "retire" and not x["removed_in_latest"]}
    new_alive = {x["atlas_id"] for x in new if x["verdict"] != "kill"}
    counts = {
        "queued_rows": len(queued),
        "queued_verdicts": dict(Counter(x["verdict"] for x in queued)),
        "queued_open_pr_rows": sum(1 for x in queued if x["open_pr"]),
        "queued_open_pr_changed": sum(1 for x in queued if x["open_pr"] and x["verdict"] != "keep"),
        "queued_removed_in_latest_rows": sum(1 for x in queued if x["removed_in_latest"]),
        "queued_quote_drift_at_bump": sum(1 for x in queued if x["quote_survives_latest"] is False),
        "queued_techniques": len({x["atlas_id"] for x in queued}),
        "queued_techniques_with_surviving_row_not_moved": len(q_tech_alive),
        "new_rows": len(new),
        "new_verdicts": dict(Counter(x["verdict"] for x in new)),
        "new_techniques": len(mem),
        "new_techniques_with_surviving_row": len(new_alive),
        "decided_by": dict(Counter(x["decided_by"] for x in queued)),
    }

    json.dump({"counts": counts, "queued": queued, "new": new,
               "new_technique_reviews": vtech,
               "new_technique_proposals": {k: {"proposals": v["new_artifact_proposals"], "event_model": v["event_model"],
                                               "residual_test": v["residual_test"], "no_fit_rationale": v["no_fit_rationale"]}
                                           for k, v in vprops.items()}},
              open(RB / "rebaseline-final.json", "w"), indent=1)

    cols = ["row_id", "atlas_id", "label", "wave", "open_pr", "old_verb", "old_artifact", "verdict", "verb",
            "artifact_iri", "evidence_quote", "removed_in_latest", "successor", "quote_survives_latest",
            "decided_by", "reason"]
    with open(PROJ / "crosswalk-rebaseline-2026-11.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(queued)
    ncols = ["atlas_id", "label", "kind", "verdict", "verb", "artifact_iri", "artifact_label", "evidence_quote",
             "mapper_verb", "mapper_artifact", "reason"]
    with open(PROJ / "crosswalk-annex-v2026.10.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=ncols, extrasaction="ignore")
        w.writeheader()
        w.writerows(new)
    print(json.dumps(counts, indent=1))


if __name__ == "__main__":
    main()
