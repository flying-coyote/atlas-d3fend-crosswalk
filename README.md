# ATLAS → D3FEND crosswalk

D3FEND infers which defensive techniques counter an offensive technique only through a shared digital artifact. A technique with no artifact restriction is invisible to that inference. In July 2026, MITRE's own D3FEND dashboard showed MITRE ATLAS at **0 of 140 techniques integrated**, so the inferred offense-defense picture had nothing to say about attacks on AI systems.

This repository maps ATLAS techniques to **existing** D3FEND artifacts. Each mapping is a restriction of the form `:AML.T#### :<verb> some :<Artifact>`, written in D3FEND's own vocabulary and justified by a verbatim quote from the technique's definition. The mappings go upstream one pull request at a time on [d3fend/d3fend-ontology](https://github.com/d3fend/d3fend-ontology), coordinated on issue [#606](https://github.com/d3fend/d3fend-ontology/issues/606). This repo is the working dataset and the audit trail behind those PRs. It is not a parallel taxonomy: where D3FEND lacks a class, the gap is recorded here and taken to the existing upstream thread instead of being invented locally.

## Where it stands (2026-11-02)

| Upstream | State |
|---|---|
| [#617](https://github.com/d3fend/d3fend-ontology/pull/617) T0021, [#618](https://github.com/d3fend/d3fend-ontology/pull/618) T0037 | merged |
| [#616](https://github.com/d3fend/d3fend-ontology/pull/616) T0008.002, [#619](https://github.com/d3fend/d3fend-ontology/pull/619) T0077 | revised per review, awaiting re-review |
| #607, #608, #609, #612, #613, #614, #615 | open |
| [#586](https://github.com/d3fend/d3fend-ontology/issues/586) / [#601](https://github.com/d3fend/d3fend-ontology/pull/601) | related: agent-tool artifact classes (not mine); this crosswalk supplies their ATLAS side |
| [mitre-atlas/atlas-data#33](https://github.com/mitre-atlas/atlas-data/issues/33) | moved ATLAS techniques vanish from STIX with no `revoked-by`, which a D3FEND ATLAS bump would turn into stale classes |

**Measured coverage.**

- **July, D3FEND 1.4.0, via MITRE's own `dashboard_report.py`:** appending the core restrictions moved ATLAS from 0 to **117 of 140** integrated (83.6%), with every other framework's counts unchanged (`data/acceptance-result.json`).
- **2026-11, develop `a24ebcc`, via MITRE's own `make dashboard`:** develop alone has 2 of 173 ATLAS techniques integrated. Develop plus `snippets/aml-rebaseline-2026-11.ttl` and the open PRs (fork branch [`atlas-full-preview`](https://github.com/flying-coyote/d3fend-ontology/tree/atlas-full-preview) @ `433c32d`) has **137 of 173** (79.2%), with every other framework's included, integrated and relationship counts unchanged (`data/acceptance-result-2026-11.json`, written by `scripts/85_compare_reports.py`). An rdflib count of ATLAS classes with a direct artifact restriction gives the same 137, and so does an independent recount.
- **Pending ATLAS ingest:** a further 45 of the 56 techniques ATLAS added in v2026.07–v2026.10 have verified mappings. D3FEND develop still ingests ATLAS v2026.06, so they have no IRIs yet.

## Files

| Path | What it is |
|---|---|
| `data/acceptance-result*.json` | MITRE dashboard before/after: July on 1.4.0, 2026-11 on develop |
| `crosswalk.csv` | core rows (ATLAS 5.1.1 IDs, the original 140), July 2026, updated with upstream rulings |
| `crosswalk-annex-v2026.06.csv` | the 33 techniques added by ATLAS v2026.06, verified July 2026 |
| `crosswalk-rebaseline-2026-11.csv` | **current queue**: every unmerged row re-adjudicated against develop `a24ebcc`, with old vs new mapping, verdict, reason and who decided |
| `crosswalk-annex-v2026.10.csv` | the 56 techniques added in ATLAS v2026.07–v2026.10 (pending ingest) |
| `snippets/*.ttl` | script-emitted restrictions, never hand-written. `aml-rebaseline-2026-11.ttl` is the current one. |
| `VERSION-DIFF-2026-11.md` | ATLAS v2026.06→v2026.10, ATT&CK v20, and D3FEND develop changes, each tagged by primary source |
| `data/develop-2026-11/` | ground truth rebuilt from D3FEND develop source: 922 artifacts, 199 verbs, ATLAS members to map, ATT&CK seeds, and a manifest with input hashes |
| `work/verify/`, `work/rebaseline/` | the evidence trail: mapper, adjudicator and verifier inputs and outputs, gate reports, and the final verdict file |
| `scripts/` | the reproducible 2026-11 pipeline (below) |

CSV columns that matter:

- `verb` / `artifact_iri`: the restriction.
- `evidence_quote`: verbatim from the technique's `d3f:definition` on develop, or from ATLAS v2026.10 for the pending annex.
- `verdict`: keep / revise / retire (queue) or keep / revise / kill (new).
- `removed_in_latest` / `successor`: ATLAS moved the technique to a new ID, so the row carries forward rather than going upstream on the old IRI.
- `quote_survives_latest`: whether the quote is still verbatim in ATLAS v2026.10, so it needs no re-quote at the next bump.

## Method

**Hard gates (deterministic, fatal on failure).**

- Every artifact IRI is a non-deprecated descendant of `d3f:Artifact` on develop.
- Every verb sits in D3FEND's `subPropertyOf` closure under its integration roots.
- Every evidence quote is a verbatim substring of the definition it will be judged against.
- ATT&CK-inherited rows match a restriction D3FEND itself asserts on the referenced ATT&CK technique.
- Generic roots (`Artifact`, `DigitalArtifact`, `Resource`, …) are rejected.

The July gate checked IRIs against the published 1.4.0 JSON-LD rather than develop, and so passed one class develop had already renamed. The 2026-11 gate reads develop source directly.

**The ontology checklist, run on every row.**

- Is the target a continuant or an occurrent?
- Is it the carrier, the content, or the act?
- Is it a kind, or a role something plays?
- Is the verb right, using `may-*` only where the definition makes the act optional?
- Is this the most specific class that is *true*? A specific-but-false target is worse than a general-but-true one.

For example, `d3f:Software` carries `contains some ExecutableFile`, so a trained model's weights map to `d3f:File`, not `Software`.

**Reviewer rulings used as calibration.**

- [#616](https://github.com/d3fend/d3fend-ontology/pull/616): assert the record an act brings into being (`creates DomainRegistration`), not the identifier (`DomainName`).
- [#619](https://github.com/d3fend/d3fend-ontology/pull/619): assert the observable traffic, not the URL.
- [#608](https://github.com/d3fend/d3fend-ontology/pull/608): collapse siblings into one restriction on their most specific common parent (`DigitalMedia`).
- [#618](https://github.com/d3fend/d3fend-ontology/pull/618): a parent class beside its children is acceptable.

**Model use, disclosed.**

- **Who did what.** Language models proposed and reviewed rows, scripts gated them, and agents never wrote TTL. Cheaper models (Claude Sonnet) did the bulk mapping and adjudication. A stronger model (Claude Opus) adversarially verified every new row, every proposed change and a stratified sample of unchanged rows.
- **Kill rates.** The July pass killed 20% of rows on verification (88 of 436). The 2026-11 pass killed 11 of 89 new rows and revised 35.
- **Agreement.** Opus disagreed with 1 of 43 sampled Sonnet keeps, and that one was the renamed class the gate also catches. Opus overrode 7 of 28 Sonnet change proposals. So the unsampled keeps are the lower-risk set, but they are model judgments, and row-level disputes are welcome.

**What doesn't fit existing D3FEND vocabulary, and where it goes.**

- **Agent tool definitions** (about a dozen techniques): [#586/#601](https://github.com/d3fend/d3fend-ontology/pull/601).
- **AI models** (16 techniques), **datasets** (5) and **agent memory** (6): the class sketch on [#606](https://github.com/d3fend/d3fend-ontology/issues/606).
- **Training / fine-tuning / inference events:** the `MachineLearningEvent` direction proposed on #606.
- **Three honest no-fits.** T0116 and T0117 describe an agent's own planning loop, which is neither an artifact nor an ML event. T0000.003 has the adversary reading a third-party scan service's results rather than acting on any victim artifact.

## Reproduce

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
# inputs: D3FEND develop src/ontology/d3fend-protege.ttl; ATLAS stix-atlas.json + dist/v6/ATLAS-<v>.yaml per release
.venv/bin/python scripts/06_build_develop_ground_truth.py --develop-ttl <d3fend-protege.ttl> --develop-commit <sha> \
    --stix-latest <stix-2026.10.json> --yaml-latest <ATLAS-2026.10.yaml> --out-dir data/develop-2026-11
.venv/bin/python scripts/03_rebaseline_check.py --develop-ttl <develop.ttl> --baseline-ttl <older.ttl> \
    --stix-ingested <stix-2026.06.json> --stix-latest <stix-2026.10.json> --out check.json
.venv/bin/python scripts/04_calibration_flags.py --develop-ttl <develop.ttl> --out flags.json
python3 scripts/20_validate.py --data-dir data/develop-2026-11 --batch-dir work/rebaseline --batch-glob 'map-B*.output.json'
.venv/bin/python scripts/07_apply_rebaseline.py      # applies verdicts, re-gates every row, writes the two 2026-11 CSVs
.venv/bin/python scripts/70_emit_ttl.py --rebaseline  # emits + parse-checks snippets/aml-rebaseline-2026-11.ttl
```

`01_diff_atlas_releases.py` and `02_attack_seed_drift.py` re-derive `VERSION-DIFF-2026-11.md`. The July mapping fan-out depended on local caches and is represented here by its outputs (`crosswalk.csv`, `work/verify/`) rather than its scripts.

## Contributing

If you think a row is wrong, open an issue here with the row and the reason; the checklist above is the frame I'll answer in. Ontology changes themselves (new classes, verbs, or edits to D3FEND's ATT&CK mappings) belong upstream on d3fend-ontology, not here.

License: MIT (see `LICENSE`). ATLAS and D3FEND material is reproduced under their own licenses (see `NOTICE`).
