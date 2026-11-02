#!/usr/bin/env python3
"""Ground truth rebuilt from D3FEND `develop` source TTL + ATLAS latest STIX (2026-11 rebaseline).

Why this exists: the July ground truth (script 00) was derived from the d3fend-wall cache of the
PUBLISHED 1.4.0 JSON-LD, so the G2 artifact-existence gate accepted `d3f:NetworkService`, a class
develop had already renamed to `NetworkServiceApplicationProcess` (#543). Gating new rows against
develop closes that hole. The July files under data/ are left untouched (they are the record of
what the July PRs were validated against); this writes to a separate directory.

Outputs (all to --out-dir):
  artifact_index.json   non-deprecated descendants of d3f:Artifact on develop (iri/label/def/path)
  artifact_digest.txt   one line per artifact, path-sorted (the mapper's in-context schema)
  verb_tree.json        subPropertyOf closure under the three integration roots + offensive usage
  all_ids.json          every d3f: subject on develop (G4 collision set)
  atlas_members.json    ATLAS techniques in latest STIX with NO class on develop (to be mapped)
  attack_seed.json      ATT&CK-inheritance seeds for those, from develop restrictions on the
                        referenced ATT&CK class (direct + subtree + ancestors, as script 00 did)
  manifest.json         input hashes + develop commit, so a reader can re-derive every count
"""
import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import rdflib
import yaml
from rdflib import OWL, RDF, RDFS, Namespace

D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")
ROOTS = ["may-be-associated-with", "semantic-relation", "enables"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def s(u):
    return "d3f:" + str(u).split("#")[-1]


def named(x):
    return isinstance(x, rdflib.URIRef) and str(x).startswith(str(D3F))


def down(g, root):
    seen, todo = {root}, [root]
    while todo:
        c = todo.pop()
        for x in g.subjects(RDFS.subClassOf, c):
            if named(x) and x not in seen:
                seen.add(x)
                todo.append(x)
    return seen


def up(g, c):
    seen, todo = {c}, [c]
    while todo:
        x = todo.pop()
        for o in g.objects(x, RDFS.subClassOf):
            if named(o) and o not in seen:
                seen.add(o)
                todo.append(o)
    return seen


def restr(g, c):
    out = set()
    for r in g.objects(c, RDFS.subClassOf):
        if (r, RDF.type, OWL.Restriction) in g:
            p, f = g.value(r, OWL.onProperty), g.value(r, OWL.someValuesFrom)
            if named(p) and named(f):
                out.add((s(p), s(f)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--develop-ttl", required=True)
    ap.add_argument("--develop-commit", required=True)
    ap.add_argument("--stix-latest", required=True)
    ap.add_argument("--yaml-latest", required=True)
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args()
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    g = rdflib.Graph()
    g.parse(a.develop_ttl, format="turtle")
    deprecated = set(g.subjects(OWL.deprecated, None))

    # artifacts
    arts = sorted((c for c in down(g, D3F.Artifact) if c not in deprecated), key=str)
    parents = {c: sorted(s(o) for o in g.objects(c, RDFS.subClassOf) if named(o)) for c in arts}

    def path(c):
        p, cur, seen = [], c, set()
        while cur is not None and cur not in seen:
            seen.add(cur)
            p.append(str(cur).split("#")[-1])
            ps = [o for o in g.objects(cur, RDFS.subClassOf) if named(o) and o in set(arts)]
            cur = sorted(ps, key=str)[0] if ps else None
        return " > ".join(reversed(p))

    index = [{"iri": s(c), "label": str(g.value(c, RDFS.label) or ""),
              "definition": str(g.value(c, D3F.definition) or ""), "parents": parents[c],
              "path": path(c)} for c in arts]
    json.dump({"count": len(index), "artifacts": index}, open(out / "artifact_index.json", "w"), indent=1)
    with open(out / "artifact_digest.txt", "w") as f:
        for x in sorted(index, key=lambda x: x["path"]):
            f.write(f"{x['iri']} | {x['label']} | {x['path']}\n")

    # verbs
    sub_of = {}
    for p, o in g.subject_objects(RDFS.subPropertyOf):
        if named(p) and named(o):
            sub_of.setdefault(p, set()).add(o)
    verbs, frontier = {}, [D3F[r] for r in ROOTS]
    while frontier:
        cur = frontier.pop()
        for p, sups in sub_of.items():
            if cur in sups and p not in verbs:
                verbs[p] = True
                frontier.append(p)
    for r in ROOTS:
        verbs[D3F[r]] = True
    off_classes = set()
    for root in ("OffensiveTechnique", "ATTACKEnterpriseTechnique", "ATTACKICSTechnique",
                 "ATTACKMobileTechnique", "ATLASTechnique", "SPARTATechnique"):
        if (D3F[root], RDF.type, OWL.Class) in g:
            off_classes |= down(g, D3F[root])
    usage = Counter()
    for c in off_classes:
        for p, _ in restr(g, c):
            usage[p] += 1
    vt = {s(v): {"label": str(g.value(v, RDFS.label) or ""), "observed_offensive_count": usage.get(s(v), 0)}
          for v in verbs}
    json.dump({"roots": [f"d3f:{r}" for r in ROOTS], "count": len(vt), "verbs": vt},
              open(out / "verb_tree.json", "w"), indent=1)

    all_ids = sorted(s(x) for x in set(g.subjects()) if named(x))
    json.dump(all_ids, open(out / "all_ids.json", "w"))

    # ATLAS members without a develop IRI
    on_dev = {str(o) for o in g.objects(None, D3F["attack-id"])}
    bundle = json.load(open(a.stix_latest))
    y = yaml.safe_load(open(a.yaml_latest))["techniques"]
    tactic_name = {o["x_mitre_shortname"]: o["name"] for o in bundle["objects"] if o["type"] == "x-mitre-tactic"}
    members = []
    for o in bundle["objects"]:
        if o["type"] != "attack-pattern":
            continue
        eid = next(r["external_id"] for r in o["external_references"] if r.get("source_name") == "mitre-atlas")
        if eid in on_dev:
            continue
        yt = y.get(eid, {})
        members.append({"atlas_id": eid, "label": o["name"], "definition": o.get("description", ""),
                        "tactics": [tactic_name.get(k["phase_name"], k["phase_name"]) for k in o.get("kill_chain_phases", [])],
                        "parent_technique": eid.rsplit(".", 1)[0] if re.match(r"AML\.T\d{4}\.\d{3}$", eid) else None,
                        "attack_reference": (yt.get("attack-reference") or {}).get("id"),
                        "maturity": yt.get("maturity")})
    members.sort(key=lambda m: m["atlas_id"])
    json.dump({"source": f"stix-atlas latest ({Path(a.stix_latest).name})", "count": len(members),
               "members": members}, open(out / "atlas_members.json", "w"), indent=1)

    atk = {str(o): sub for sub, o in g.subject_objects(D3F["attack-id"])}
    seeds = []
    for m in members:
        ref = m["attack_reference"]
        if not ref:
            continue
        node = atk.get(ref)
        pairs = set()
        if node is not None and node not in deprecated:
            for c in down(g, node) | up(g, node):
                pairs |= restr(g, c)
        art_iris = {x["iri"] for x in index}
        by_art = {}
        for v, art in sorted(pairs):
            if art not in art_iris:
                continue  # upper-ontology fillers (Access, OffensiveTactic, TA00xx) are not artifacts
            by_art.setdefault(art, []).append(v)
        seeds.append({"atlas_id": m["atlas_id"], "attack_id": ref,
                      "attack_class_on_develop": node is not None,
                      "attack_deprecated": node in deprecated if node is not None else None,
                      "seed_status": "seeded" if by_art else "attack-unmapped",
                      "artifacts": [{"iri": k, "verbs": v} for k, v in sorted(by_art.items())]})
    json.dump({"count": len(seeds), "seeded": sum(1 for x in seeds if x["artifacts"]), "seeds": seeds},
              open(out / "attack_seed.json", "w"), indent=1)

    manifest = {"develop_commit": a.develop_commit, "develop_ttl_sha256": sha(a.develop_ttl),
                "stix_latest": Path(a.stix_latest).name, "stix_sha256": sha(a.stix_latest),
                "yaml_latest": Path(a.yaml_latest).name, "yaml_sha256": sha(a.yaml_latest),
                "artifact_count": len(index), "verb_count": len(vt), "members_to_map": len(members),
                "seeds": len(seeds), "seeded": sum(1 for x in seeds if x["artifacts"])}
    json.dump(manifest, open(out / "manifest.json", "w"), indent=1)
    print(json.dumps(manifest, indent=1))


if __name__ == "__main__":
    main()
