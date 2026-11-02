#!/usr/bin/env python3
"""Check whether D3FEND's ATT&CK restrictions behind the ATLAS->ATT&CK inheritance seeds moved.

Usage: 02_attack_seed_drift.py <baseline d3fend-protege.ttl> <develop d3fend-protege.ttl> data/attack_seed-2026-07.json
Compares restrictions on each referenced ATT&CK class plus its subtree and ancestors (the method the seeds were built with).
"""
import json,sys,rdflib
from rdflib import RDF,RDFS,OWL,Namespace
D3F=Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")
def load(p):
    g=rdflib.Graph(); g.parse(p,format="turtle"); return g
def ids(g): return {str(o):s for s,o in g.subject_objects(D3F["attack-id"])}
def sub(g,c):
    seen,todo={c},[c]
    while todo:
        x=todo.pop()
        for s in g.subjects(RDFS.subClassOf,x):
            if s not in seen and isinstance(s,rdflib.URIRef): seen.add(s);todo.append(s)
    return seen
def anc(g,c):
    seen,todo={c},[c]
    while todo:
        x=todo.pop()
        for s in g.objects(x,RDFS.subClassOf):
            if s not in seen and isinstance(s,rdflib.URIRef): seen.add(s);todo.append(s)
    return seen
def restr(g,cs):
    out=set()
    for c in cs:
        for r in g.objects(c,RDFS.subClassOf):
            if (r,RDF.type,OWL.Restriction) in g:
                p,f=g.value(r,OWL.onProperty),g.value(r,OWL.someValuesFrom)
                if p is not None and f is not None: out.add(("d3f:"+str(p).split('#')[1],"d3f:"+str(f).split('#')[1]))
    return out
gb,gd=load(sys.argv[1]),load(sys.argv[2])
ib,idv=ids(gb),ids(gd)
seeds=json.load(open(sys.argv[3]))["seeds"]
for s in seeds:
    a=s["attack_id"]
    if a not in ib and a not in idv: print(a,"absent both"); continue
    if a not in idv: print(a,"REMOVED on develop"); continue
    if a not in ib: print(a,"new on develop"); continue
    for nm,fn in (("subtree",sub),("ancestors",anc)):
        b=restr(gb,fn(gb,ib[a])); d=restr(gd,fn(gd,idv[a]))
        if b!=d: print(s["atlas_id"],a,nm,"lost",sorted(b-d),"gained",sorted(d-b))
    dep=gd.value(idv[a],OWL.deprecated)
    if dep: print(a,"DEPRECATED on develop")
    lb=gb.value(ib[a],RDFS.label); ld=gd.value(idv[a],RDFS.label)
    if lb!=ld: print(a,"label",lb,"->",ld)
print("done",len(seeds))
