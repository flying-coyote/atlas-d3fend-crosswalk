#!/usr/bin/env python3
"""The deterministic HARD GATE for mapper/verifier/consolidation outputs.

Checks (fatal = row rejected; structural = run halted):
  G1  coverage: every member id appears in exactly one output row set (structural)
  G2  artifact existence: every artifact_iri / nearest_existing_iri / parent_iri
      exact-matches the 915-class d3f:Artifact closure (with --family, canonical
      proposed names are also accepted as mapping targets)
  G3  verb existence: verb is in the subPropertyOf closure under the three
      integration roots; warn if never observed on an offensive technique
  G4  new-artifact shape: CamelCase name, no collision with ANY existing @id
  G5  inheritance integrity: attack_inherited rows must match attack_seed.json
  G6  evidence anti-hallucination: evidence_quote must be a (whitespace-normalized)
      verbatim substring of the technique's own definition
  G7  generic-target denylist + >15% single-artifact concentration flag

Usage: 20_validate.py [--annex] [--family work/consolidation/artifact_family.json]
       20_validate.py --data-dir data/develop-2026-11 --batch-dir work/rebaseline --batch-glob 'map-B*.output.json'
         (2026-11 rebaseline: gate against D3FEND develop instead of the July 1.4.0-derived files;
          G1 expects every member in <data-dir>/atlas_members.json; G4 collisions from all_ids.json)
Writes work/validation-{core|annex}.json ; exits non-zero on structural failure.
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJ = HERE.parent
DATA = PROJ / "data"
WORK = PROJ / "work"

DENYLIST = {"d3f:Artifact", "d3f:DigitalArtifact", "d3f:Resource",
            "d3f:DigitalInformation", "d3f:DigitalInformationBearer", "d3f:UserAction"}
NAME_RE = re.compile(r"^[A-Z][A-Za-z0-9]+$")


def norm(s):
    return re.sub(r"\s+", " ", (s or "").strip())


def canon_verb(v):
    """Accept a bare ('accesses') or prefixed ('d3f:accesses') verb; return the prefixed form.

    off_artifacts.json (and therefore the seed rows handed to mappers) carries bare verbs while
    the ontology and the emitted TTL use the prefixed form, so agents legitimately echoed both.
    The gate canonicalizes rather than punishing whichever form an agent happened to copy; the
    kept rows are rewritten in place so everything downstream sees one form.
    """
    if not v:
        return v
    return v if v.startswith("d3f:") else f"d3f:{v}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--annex", action="store_true")
    ap.add_argument("--family", type=Path, default=None)
    ap.add_argument("--data-dir", type=Path, default=None)
    ap.add_argument("--batch-dir", type=Path, default=None)
    ap.add_argument("--batch-glob", default="*.output.json")
    args = ap.parse_args()
    data = args.data_dir or DATA

    members = json.load(open(data / "atlas_members.json"))["members"]
    defs = {m["atlas_id"]: m["definition"] for m in members}
    expected = {m["atlas_id"] for m in members}
    if args.annex:
        skew = json.load(open(DATA / "version_skew.json"))
        expected = set(skew["newer_only"])
        defs = {}
        for f in sorted((WORK / "annex").glob("batch-A*.input.json")):
            for t in json.load(open(f))["techniques"]:
                defs[t["atlas_id"]] = t["definition"]

    art_ids = {a["iri"] for a in json.load(open(data / "artifact_index.json"))["artifacts"]}
    verbs = set(json.load(open(data / "verb_tree.json"))["verbs"])
    observed = {v for v, meta in json.load(open(data / "verb_tree.json"))["verbs"].items()
                if meta["observed_offensive_count"]}
    seeds = {s["atlas_id"]: {(a["iri"], canon_verb(v)) for a in s["artifacts"] for v in a["verbs"]}
             for s in json.load(open(data / "attack_seed.json"))["seeds"]}
    if args.data_dir:
        all_ids = set(json.load(open(data / "all_ids.json")))
    else:
        # collision set: every @id in the full ontology graph (July mode: the published JSON-LD)
        import os
        jsonld = os.environ.get("D3FEND_JSONLD")
        if not jsonld:
            raise SystemExit("July mode needs D3FEND_JSONLD=<path to d3fend.json>; or use --data-dir")
        graph = json.load(open(jsonld))["@graph"]
        all_ids = {n.get("@id") for n in graph if isinstance(n.get("@id"), str)}

    family_names = set()
    if args.family and args.family.exists():
        fam = json.load(open(args.family))
        family_names = {c["canonical_name"] for c in fam["classes"]}

    outdir = args.batch_dir or (WORK / ("annex" if args.annex else "batches"))
    rows_by_tech, problems, warnings = {}, [], []
    for f in sorted(outdir.glob(args.batch_glob)):
        out = json.load(open(f))
        for t in out.get("techniques", []):
            tid = t.get("atlas_id")
            if tid in rows_by_tech:
                problems.append(f"STRUCTURAL duplicate technique {tid} (second in {f.name})")
            rows_by_tech[tid] = (t, f.name)

    missing = expected - set(rows_by_tech)
    extra = set(rows_by_tech) - expected
    if missing or extra:
        problems.append(f"STRUCTURAL G1: missing={sorted(missing)} extra={sorted(extra)}")

    target_counter = Counter()
    n_rows = 0
    results = {}
    for tid, (t, src) in sorted(rows_by_tech.items()):
        rejects, keeps = [], {"mappings": [], "new_artifact_proposals": [], "attack_inherited": []}
        definition = norm(defs.get(tid, ""))

        for m in t.get("mappings", []):
            n_rows += 1
            m["verb"] = canon_verb(m.get("verb"))
            iri, verb, quote = m.get("artifact_iri"), m["verb"], m.get("evidence_quote")
            errs = []
            if iri not in art_ids and iri not in family_names:
                errs.append(f"G2 unknown artifact {iri!r}")
            if verb not in verbs:
                errs.append(f"G3 unknown verb {verb!r}")
            elif verb not in observed:
                warnings.append(f"{tid}: verb {verb} never observed offensively")
            if iri in DENYLIST:
                errs.append(f"G7 denylisted generic target {iri}")
            if not quote or norm(quote) not in definition:
                errs.append("G6 evidence_quote is not a verbatim substring of the definition")
            (rejects.append({**m, "errors": errs}) if errs else keeps["mappings"].append(m))
            if not errs:
                target_counter[iri] += 1

        for p in t.get("new_artifact_proposals", []):
            n_rows += 1
            errs = []
            if p.get("parent_iri") not in art_ids:
                errs.append(f"G4 parent {p.get('parent_iri')!r} not in closure")
            nm = p.get("proposed_name", "")
            if not NAME_RE.match(nm):
                errs.append(f"G4 name {nm!r} not CamelCase")
            if f"d3f:{nm}" in all_ids:
                errs.append(f"G4 name d3f:{nm} collides with an existing class")
            if p.get("nearest_existing_iri") not in art_ids:
                errs.append(f"G4 nearest_existing_iri {p.get('nearest_existing_iri')!r} not in closure")
            p["verb"] = canon_verb(p.get("verb"))
            v = p["verb"]
            if v and v not in verbs:
                errs.append(f"G3 unknown verb {v!r}")
            q = p.get("evidence_quote")
            if not q or norm(q) not in definition:
                errs.append("G6 evidence_quote is not a verbatim substring of the definition")
            (rejects.append({**p, "errors": errs}) if errs
             else keeps["new_artifact_proposals"].append(p))

        seedset = seeds.get(tid, set())
        for h in t.get("attack_inherited", []):
            n_rows += 1
            h["verb"] = canon_verb(h.get("verb"))
            pair = (h.get("artifact_iri"), h["verb"])
            if pair not in seedset:
                rejects.append({**h, "errors": [f"G5 inherited pair {pair} not in seed"]})
            else:
                keeps["attack_inherited"].append(h)
                target_counter[h.get("artifact_iri")] += 1

        disp = t.get("disposition")
        if disp == "maps-existing" and not keeps["mappings"]:
            disp_note = "disposition maps-existing but no surviving mappings"
        elif disp == "needs-new-artifact" and not keeps["new_artifact_proposals"]:
            disp_note = "disposition needs-new-artifact but no surviving proposals"
        elif disp == "attack-inherited-only" and not keeps["attack_inherited"]:
            disp_note = "disposition attack-inherited-only but no surviving inherited rows"
        elif disp == "no-fit" and not norm(t.get("no_fit_rationale", "")):
            disp_note = "disposition no-fit without rationale"
        else:
            disp_note = None

        results[tid] = {"source": src, "disposition": disp, "keeps": keeps,
                        "rejects": rejects, "disposition_note": disp_note,
                        "no_fit_rationale": t.get("no_fit_rationale")}

    total_kept = sum(len(r["keeps"]["mappings"]) + len(r["keeps"]["attack_inherited"])
                     for r in results.values())
    conc = [(iri, c) for iri, c in target_counter.most_common()
            if total_kept and c / total_kept > 0.15]
    for iri, c in conc:
        warnings.append(f"G7 CONCENTRATION: {iri} targeted by {c}/{total_kept} kept rows (>15%)")

    n_rej = sum(len(r["rejects"]) for r in results.values())
    n_dispnote = sum(1 for r in results.values() if r["disposition_note"])
    report = {"stage": "annex" if args.annex else "core",
              "techniques": len(results), "rows_seen": n_rows,
              "rows_rejected": n_rej, "disposition_notes": n_dispnote,
              "structural_problems": problems, "warnings": warnings,
              "results": results}
    out = (outdir / "validation-rebaseline.json") if args.batch_dir else WORK / f"validation-{'annex' if args.annex else 'core'}.json"
    json.dump(report, open(out, "w"), indent=1)
    print(f"{out.name}: {len(results)} techniques, {n_rows} rows, {n_rej} rejected, "
          f"{n_dispnote} disposition notes, {len(problems)} structural, {len(warnings)} warnings")
    for p in problems:
        print("  !!", p)
    for w in warnings[:12]:
        print("  ~", w)
    if problems:
        sys.exit(1)


if __name__ == "__main__":
    main()
