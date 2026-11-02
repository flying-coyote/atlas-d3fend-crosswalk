#!/usr/bin/env python3
"""Mechanical calibration flags (2026-11): apply the maintainers' rulings as deterministic checks.

Rulings encoded (calibration data, not my taxonomy):
  F616  the act brings a record into being -> flag identifier targets under uses/accesses
        (#616: acquiring a domain `creates DomainRegistration`, not `uses DomainName`)
  F619  carrier-level detail asserted as a product -> flag identifier targets under produces
        (#619: "Agree on the traffic, not sure about this URL")
  F608  sibling restrictions with one verb -> report their least common ancestor so a human can
        decide whether one restriction on the most specific COMMON parent is cleaner (#608)
  F618  parent alongside its own child under the same verb -> informational only; #618 merged a
        bare ATT&CK-inherited `:File` beside its children, so this is accepted, not a defect
  FMAY  may-X and X on the same artifact -> redundant hedge
  FGEN  target sits at a generic level (File, Software, Resource, DigitalArtifact...) -> run the
        specificity question by hand

Reads the develop TTL directly. Writes one JSON with per-row flags and per-technique groups.
"""
import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

import rdflib
from rdflib import RDFS, Namespace

D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")
PROJ = Path(__file__).resolve().parent.parent
GENERIC = {"File", "Software", "Resource", "DigitalArtifact", "DigitalInformation", "Artifact",
           "Application", "DigitalMessage", "NetworkTraffic", "WebResource", "Process"}
ROOTS = {"Artifact", "DigitalArtifact", "DigitalInformation", "DigitalInformationBearer",
         "Thing", "PhysicalArtifact"}


def ancestors(g, c):
    seen, todo = {c}, [c]
    while todo:
        x = todo.pop()
        for o in g.objects(x, RDFS.subClassOf):
            if isinstance(o, rdflib.URIRef) and o not in seen:
                seen.add(o)
                todo.append(o)
    return seen


def depth(g, c, memo):
    if c in memo:
        return memo[c]
    memo[c] = 0
    ps = [o for o in g.objects(c, RDFS.subClassOf) if isinstance(o, rdflib.URIRef)]
    memo[c] = 1 + max((depth(g, p, memo) for p in ps), default=-1)
    return memo[c]


def lca(g, classes, memo):
    common = set.intersection(*(ancestors(g, c) for c in classes))
    if not common:
        return None
    return max(common, key=lambda c: depth(g, c, memo))


def n(u):
    return str(u).split("#")[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--develop-ttl", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    g = rdflib.Graph()
    g.parse(a.develop_ttl, format="turtle")
    memo = {}
    ident = D3F.Identifier

    rows = []
    for fname, wave in (("crosswalk.csv", "core"), ("crosswalk-annex-v2026.06.csv", "annex")):
        for r in csv.DictReader(open(PROJ / fname)):
            if not r.get("artifact_iri", "").startswith("d3f:"):
                continue
            art = D3F[r["artifact_iri"][4:]]
            verb = r["verb"][4:]
            base = verb.replace("may-", "")
            anc = ancestors(g, art)
            flags = []
            if ident in anc and base in ("uses", "accesses", "reads"):
                flags.append("F616")
            if ident in anc and base in ("produces", "creates"):
                flags.append("F619")
            if n(art) in GENERIC:
                flags.append("FGEN")
            rows.append({"wave": wave, "atlas_id": r["atlas_id"], "verb": verb, "base": base,
                         "artifact": n(art), "disposition": r["disposition"],
                         "evidence_quote": r["evidence_quote"], "flags": flags})

    by = defaultdict(list)
    for x in rows:
        by[(x["atlas_id"], x["base"])].append(x)
    groups = []
    for (tid, base), xs in sorted(by.items()):
        arts = sorted({x["artifact"] for x in xs})
        verbs = {x["artifact"]: {y["verb"] for y in xs if y["artifact"] == x["artifact"]} for x in xs}
        for art, vs in verbs.items():
            if base in vs and f"may-{base}" in vs:
                for x in xs:
                    if x["artifact"] == art and "FMAY" not in x["flags"]:
                        x["flags"].append("FMAY")
        if len(arts) < 2:
            continue
        uris = [D3F[x] for x in arts]
        l = lca(g, uris, memo)
        parent_child = [(n(p), n(c)) for p in uris for c in uris if p != c and p in ancestors(g, c)]
        groups.append({"atlas_id": tid, "base_verb": base, "artifacts": arts,
                       "lca": n(l) if l is not None else None,
                       "lca_is_root": (n(l) in ROOTS) if l is not None else True,
                       "parent_child": parent_child,
                       "F608_candidate": l is not None and n(l) not in ROOTS and n(l) not in arts,
                       "F618_info": bool(parent_child)})
        for x in xs:
            if groups[-1]["F608_candidate"] and "F608" not in x["flags"]:
                x["flags"].append("F608")
            if parent_child and "F618" not in x["flags"]:
                x["flags"].append("F618")

    out = {"rows": rows, "groups": groups,
           "counts": {f: sum(1 for x in rows if f in x["flags"])
                      for f in ("F616", "F619", "F608", "F618", "FMAY", "FGEN")}}
    json.dump(out, open(a.out, "w"), indent=1)
    print(json.dumps(out["counts"]))
    for gr in groups:
        if gr["F608_candidate"] or gr["F618_info"]:
            print(gr["atlas_id"], gr["base_verb"], gr["artifacts"], "LCA", gr["lca"],
                  "parent/child" if gr["parent_child"] else "")
    for x in rows:
        if {"F616", "F619", "FMAY"} & set(x["flags"]):
            print(x["atlas_id"], x["verb"], x["artifact"], x["flags"])


if __name__ == "__main__":
    main()
