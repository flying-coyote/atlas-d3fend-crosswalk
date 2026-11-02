#!/usr/bin/env python3
"""Rebaseline gate (2026-11): re-verify every queued crosswalk row against the CURRENT primaries.

Deterministic, no agent input. Reads the D3FEND source TTL directly (not the d3fend-wall JSON-LD
cache, which predates 1.5.0/1.6.0) plus two ATLAS STIX bundles: the one D3FEND develop ingests
today and the latest atlas-data release.

Per row (core crosswalk.csv + annex crosswalk-annex-v2026.06.csv):
  R1  artifact IRI is a declared owl:Class on develop, a descendant of d3f:Artifact, not deprecated
  R2  verb is a declared owl:ObjectProperty on develop
  R3  evidence quote is a verbatim substring of the develop d3f:definition (what a PR is judged on)
  R4  evidence quote is a verbatim substring of the latest ATLAS description (what survives the
      next ATLAS bump); techniques removed in latest are reported with their successor if known
  R5  attack-inherited rows: the (verb, artifact) pair is still asserted on the referenced ATT&CK
      technique on develop (ATT&CK v20 ingest)

Global:
  G1  classes added on develop since the July baseline whose IRI/label hits AI/ML/agent/model terms
  G2  any MachineLearning*Event / AIModel / Dataset-type class now present
  G3  proposed-new class names (residual + Kirillov MVP v2 + event family) present upstream?

Usage:
  03_rebaseline_check.py --develop-ttl X --baseline-ttl Y --stix-ingested A.json --stix-latest B.json --out out.json
"""
import argparse
import csv
import json
import re
from pathlib import Path

import rdflib
from rdflib import OWL, RDF, RDFS, Namespace

D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")
HERE = Path(__file__).resolve().parent
PROJ = HERE.parent

# Successors stated in the ATLAS release notes (v2026.07 and v2026.10). ATLAS STIX carries no
# revoked-by relationship for these, so the mapping has to come from the notes.
SUCCESSOR = {
    "AML.T0019": "AML.T0115.000",
    "AML.T0058": "AML.T0115.001",  # notes print .000 three times (typo); sub-IDs verified in the v2026.10 YAML
    "AML.T0104": "AML.T0115.002",
    "AML.T0024.000": "AML.T0137.000",
    "AML.T0024.001": "AML.T0137.002",
    "AML.T0024.002": "AML.T0005.001",  # NOT in the notes; inferred: v2026.10 T0024 text routes extraction to T0005.001
    "AML.T0056": "AML.T0085.003",
    "AML.T0057": "AML.T0085.002",
}

PROPOSED = ["MachineLearningModel", "RAGDataSource", "AIAgentToolDefinition", "AIModel",
            "AIInteractionMessage", "AIToolInvocation", "ProvenanceAttestation", "Dataset",
            "AIToolDefinition", "MachineLearningEvent", "MachineLearningTrainingEvent",
            "MachineLearningInferenceEvent", "MachineLearningFineTuningEvent", "AIAgent",
            "ArtificialIntelligenceAgent", "Prompt", "VectorStore"]
AI_TERMS = re.compile(r"(machine.?learning|\bML\b|artificial.?intel|\bAI\b|agent|model|prompt|"
                      r"dataset|embedding|vector|inference|training|LLM|neural)", re.I)


def stix_index(path):
    b = json.load(open(path))
    out = {}
    for o in b["objects"]:
        if o["type"] != "attack-pattern":
            continue
        eid = next(r["external_id"] for r in o["external_references"] if r.get("source_name") == "mitre-atlas")
        out[eid] = {"name": o["name"], "desc": o.get("description", "")}
    return out


def norm(s):
    return re.sub(r"\s+", " ", s or "").strip()


def load(path):
    g = rdflib.Graph()
    g.parse(path, format="turtle")
    return g


def closure_down(g, root):
    seen, todo = {root}, [root]
    while todo:
        c = todo.pop()
        for s in g.subjects(RDFS.subClassOf, c):
            if isinstance(s, rdflib.URIRef) and s not in seen:
                seen.add(s)
                todo.append(s)
    return seen


def closure_up(g, c):
    seen, todo = {c}, [c]
    while todo:
        x = todo.pop()
        for o in g.objects(x, RDFS.subClassOf):
            if isinstance(o, rdflib.URIRef) and o not in seen:
                seen.add(o)
                todo.append(o)
    return seen


def restrictions(g, cls):
    out = set()
    for r in g.objects(cls, RDFS.subClassOf):
        if (r, RDF.type, OWL.Restriction) in g:
            p = g.value(r, OWL.onProperty)
            f = g.value(r, OWL.someValuesFrom)
            if p is not None and f is not None:
                out.add((p, f))
    return out


def by_attack_id(g):
    m = {}
    for s, o in g.subject_objects(D3F["attack-id"]):
        m[str(o)] = s
    return m


def short(u):
    return "d3f:" + str(u).split("#")[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--develop-ttl", required=True)
    ap.add_argument("--baseline-ttl", required=True)
    ap.add_argument("--stix-ingested", required=True)
    ap.add_argument("--stix-latest", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    g = load(a.develop_ttl)
    gb = load(a.baseline_ttl)
    ingested = stix_index(a.stix_ingested)
    latest = stix_index(a.stix_latest)

    artifacts = closure_down(g, D3F.Artifact)
    deprecated = {s for s in g.subjects(OWL.deprecated, None)}
    classes = set(g.subjects(RDF.type, OWL.Class))
    props = set(g.subjects(RDF.type, OWL.ObjectProperty))
    ids = by_attack_id(g)

    rows = []
    for fname, wave in (("crosswalk.csv", "core"), ("crosswalk-annex-v2026.06.csv", "annex")):
        for r in csv.DictReader(open(PROJ / fname)):
            if not r.get("artifact_iri", "").startswith("d3f:"):
                continue
            tid = r["atlas_id"]
            iri = D3F[r["artifact_iri"][4:]]
            verb = D3F[r["verb"][4:]] if r["verb"].startswith("d3f:") else None
            q = norm(r.get("evidence_quote"))
            node = ids.get(tid)
            ddef = norm(str(g.value(node, D3F.definition))) if node is not None else ""
            res = {
                "wave": wave, "atlas_id": tid, "verb": r["verb"], "artifact": r["artifact_iri"],
                "disposition": r["disposition"],
                "R1_artifact_ok": iri in classes and iri in artifacts and iri not in deprecated,
                "R2_verb_ok": verb in props if verb is not None else False,
                "R3_quote_in_develop": (q in ddef) if q else None,
                "in_latest_atlas": tid in latest,
                "successor": SUCCESSOR.get(tid) if tid not in latest else None,
                "R4_quote_in_latest": None,
                "desc_changed_since_ingest": (tid in latest and tid in ingested
                                              and norm(latest[tid]["desc"]) != norm(ingested[tid]["desc"])),
                "name_latest": latest.get(tid, {}).get("name"),
            }
            src = tid if tid in latest else SUCCESSOR.get(tid)
            if q and src and src in latest:
                res["R4_quote_in_latest"] = q in norm(latest[src]["desc"])
            if r["disposition"] == "attack-inherited":
                m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", r.get("notes", "") + " " + r.get("provenance", ""))
                res["R5_attack_ref"] = m.group(0) if m else None
            rows.append(res)

    # R5 against the seed file (attack ids live there, not in the CSV)
    seeds = json.load(open(PROJ / "data" / "attack_seed.json"))["seeds"]
    seed_checks = []
    for s in seeds:
        if not s.get("artifacts"):
            continue
        node = ids.get(s["attack_id"])
        cur = set()
        if node is not None:
            for c in closure_down(g, node) | closure_up(g, node):
                cur |= {(short(p), short(f)) for p, f in restrictions(g, c)}
        for art in s["artifacts"]:
            for v in art.get("verbs", []):
                pair = (v if v.startswith("d3f:") else "d3f:" + v, art["iri"])
                seed_checks.append({"atlas_id": s["atlas_id"], "attack_id": s["attack_id"],
                                    "verb": pair[0], "artifact": pair[1],
                                    "attack_class_present": node is not None,
                                    "still_asserted_on_develop": pair in cur,
                                    "develop_pairs": sorted(cur)})

    # Globals
    new_classes = sorted(short(c) for c in (classes - set(gb.subjects(RDF.type, OWL.Class)))
                         if isinstance(c, rdflib.URIRef) and str(c).startswith(str(D3F)))
    ai_new = []
    for c in new_classes:
        u = D3F[c[4:]]
        lbl = str(g.value(u, RDFS.label) or "")
        aid = str(g.value(u, D3F["attack-id"]) or "")
        if aid:
            continue
        if AI_TERMS.search(c) or AI_TERMS.search(lbl):
            ai_new.append({"iri": c, "label": lbl, "is_artifact": u in artifacts})
    all_ai_named = sorted({short(c) for c in classes if isinstance(c, rdflib.URIRef)
                           and str(c).startswith(str(D3F)) and not g.value(c, D3F["attack-id"])
                           and re.search(r"(MachineLearning|ArtificialIntelligence|^AI|LLM|Agent|Model$|Prompt|Dataset)",
                                         str(c).split("#")[-1])})
    proposed_present = {p: (D3F[p] in classes) for p in PROPOSED}
    ml_event = [short(c) for c in classes if "MachineLearning" in str(c)]

    atlas_on_develop = sorted(k for k in ids if k.startswith("AML.T") and not k.startswith("AML.TA"))
    summary = {
        "rows": len(rows),
        "R1_fail": [x for x in rows if not x["R1_artifact_ok"]],
        "R2_fail": [x for x in rows if not x["R2_verb_ok"]],
        "R3_fail": [x for x in rows if x["R3_quote_in_develop"] is False],
        "R4_fail": [x for x in rows if x["R4_quote_in_latest"] is False],
        "removed_in_latest": sorted({x["atlas_id"] for x in rows if not x["in_latest_atlas"]}),
        "desc_changed_rows": sorted({x["atlas_id"] for x in rows if x["desc_changed_since_ingest"]}),
        "R5_seed_pairs": len(seed_checks),
        "R5_fail": [x for x in seed_checks if not x["still_asserted_on_develop"]],
        "G1_new_classes_since_baseline": len(new_classes),
        "G1_ai_terms_new": ai_new,
        "G2_ml_event_classes": ml_event,
        "G3_proposed_present": proposed_present,
        "ai_named_classes_on_develop": all_ai_named,
        "atlas_techniques_on_develop": len(atlas_on_develop),
        "atlas_latest_count": len(latest),
        "atlas_ingested_count": len(ingested),
    }
    json.dump({"summary": summary, "rows": rows, "seed_checks": seed_checks,
               "new_classes": new_classes}, open(a.out, "w"), indent=1)
    for k, v in summary.items():
        print(k, len(v) if isinstance(v, list) else v)


if __name__ == "__main__":
    main()
