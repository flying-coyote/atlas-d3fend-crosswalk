#!/usr/bin/env python3
"""Diff MITRE ATLAS releases from their STIX bundles (techniques + sub-techniques).

Usage: 01_diff_atlas_releases.py <dir with stix-2026.06.json ... stix-2026.10.json> <diff.json> <latest-techniques.json>
Bundles: https://github.com/mitre-atlas/atlas-data/releases (asset stix-atlas.json, renamed per version).
"""
import json,sys
V=['2026.06','2026.07','2026.08','2026.09','2026.10']
def load(v):
    b=json.load(open(f'{sys.argv[1]}/stix-{v}.json'))
    out={}
    for o in b['objects']:
        if o['type']!='attack-pattern': continue
        if o.get('revoked') or o.get('x_mitre_deprecated'): print('DEPFLAG',v,o['name'])
        eid=[r['external_id'] for r in o['external_references'] if r.get('source_name')=='mitre-atlas'][0]
        out[eid]={'name':o['name'],'desc':o.get('description',''),'tactics':[k['phase_name'] for k in o.get('kill_chain_phases',[])],'modified':o['modified']}
    return out
D={v:load(v) for v in V}
res={'counts':{v:len(D[v]) for v in V},'steps':{}}
for a,b in zip(V,V[1:]):
    A,B=D[a],D[b]
    res['steps'][f'{a}->{b}']={
     'added':sorted(set(B)-set(A)),'removed':sorted(set(A)-set(B)),
     'renamed':sorted([(k,A[k]['name'],B[k]['name']) for k in set(A)&set(B) if A[k]['name']!=B[k]['name']]),
     'desc_changed':sorted([k for k in set(A)&set(B) if A[k]['desc']!=B[k]['desc']])}
A,B=D[V[0]],D[V[-1]]
res['net']={'added':sorted(set(B)-set(A)),'removed':sorted(set(A)-set(B)),
 'desc_changed':sorted([k for k in set(A)&set(B) if A[k]['desc']!=B[k]['desc']]),
 'renamed':sorted([(k,A[k]['name'],B[k]['name']) for k in set(A)&set(B) if A[k]['name']!=B[k]['name']])}
res['names_latest']={k:v['name'] for k,v in B.items()}
res['names_06']={k:v['name'] for k,v in A.items()}
json.dump(res,open(sys.argv[2],'w'),indent=1)
json.dump({k:v for k,v in B.items()},open(sys.argv[3],'w'),indent=1)
print(res['counts'])
for s,x in res['steps'].items(): print(s,{k:len(v) for k,v in x.items()})
print('NET',{k:len(v) for k,v in res['net'].items()})
print('removed',res['net']['removed'])
