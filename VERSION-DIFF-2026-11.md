# Version diff, 2026-11-02

This file records what moved under the ATLAS→D3FEND crosswalk between the July 2026 build and 2026-11-02, with every count derived from a primary source and tagged by that source. Two dates matter for scope. ATLAS is at **v2026.10** (released 2026-10-28, data format v6.1.0), four releases past the v2026.06 that D3FEND develop ingests. The autonomous-agent techniques AML.T0116–T0124 arrived in **v2026.08**; v2026.09 added T0129–T0134 and the T0006 sub-techniques.

Sources and how to re-derive:

- **[ATLAS-STIX]** `stix-atlas.json` release assets for v2026.06, .07, .08, .09, .10 from `mitre-atlas/atlas-data` (the file D3FEND's `update_atlas.sh` ingests). Diff script: `scripts/01_diff_atlas_releases.py <dir-of-stix-bundles> <out.json> <latest-techniques.json>`; counts below are `attack-pattern` objects keyed by `mitre-atlas` external id.
- **[ATLAS-YAML]** `dist/v6/ATLAS-2026.06.yaml` … `ATLAS-2026.10.yaml` at tag v2026.10 (used for sub-technique names and `attack-reference`; note `dist/ATLAS.yaml` and `dist/ATLAS-latest.yaml` at the tags are a frozen legacy file and a 20-byte symlink, so do not use them).
- **[ATLAS-NOTES]** GitHub release bodies v2026.07–v2026.10.
- **[ATTACK-STIX]** `enterprise-attack-20.0.json` from `mitre-attack/attack-stix-data` (the URL D3FEND's Makefile uses).
- **[D3F-DEV]** `d3fend/d3fend-ontology` `develop` @ `a24ebcc` (2026-10-15), source `src/ontology/d3fend-protege.ttl`, compared against the July baseline `12e2762`; CHANGELOG.md for 1.5.0/1.6.0. Scripts: `scripts/03_rebaseline_check.py`, `scripts/06_build_develop_ground_truth.py` (outputs + input hashes in `data/develop-2026-11/manifest.json`).

## 1. ATLAS

**Counts [ATLAS-STIX]** (techniques + sub-techniques): v2026.06 **173** → v2026.07 178 → v2026.08 197 → v2026.09 208 → v2026.10 **221**. Net: **56 added, 8 removed, 12 renamed, 68 definitions changed** among the 165 v2026.06 IDs that survive.

| Step | Added | Removed | Renamed | Definition changed |
|---|---|---|---|---|
| 06→07 | 8 | 3 | 1 | 41 |
| 07→08 | 19 | 0 | 3 | 5 |
| 08→09 | 11 | 0 | 0 | 9 |
| 09→10 | 18 | 5 | 8 | 43 |

### Added, by release [ATLAS-STIX]

- **v2026.07 (+8):** `AML.T0018.003` Modify Prompt Construction Logic, `AML.T0110.000` Definition and Instructions, `AML.T0110.001` Implementation, `AML.T0110.002` Runtime Response, `AML.T0115` Publish Poisoned AI Artifacts, `AML.T0115.000` Datasets, `AML.T0115.001` Models, `AML.T0115.002` AI Agent Tools
- **v2026.08 (+19):** `AML.T0016.003` Exploits, `AML.T0016.004` AI Agent Tools, `AML.T0017.001` Autonomous Exploit Development, `AML.T0017.002` AI Agent Tools, `AML.T0116` Autonomous Reconnaissance, `AML.T0117` Autonomous Attack-Path Adaptation, `AML.T0118` Autonomous AI Agent Communication, `AML.T0118.000` Communication via Shared Artifacts, `AML.T0118.001` Direct Agent Communication, `AML.T0119` Exploit Automated Artifact Processing Pipeline, `AML.T0120` AI Artifact Repository, `AML.T0121` AI Agent Environment Reconstruction, `AML.T0122` Exploitation of Remote Services, `AML.T0123` Obfuscated Files or Information, `AML.T0124` Autonomous Attack Orchestration, `AML.T0125` Create Account, `AML.T0126` Automated Collection, `AML.T0127` Data Staged, `AML.T0128` Compromise Infrastructure
- **v2026.09 (+11):** `AML.T0000.003` Scan Databases, `AML.T0006.000` Enumerate Hosted AI Resources, `AML.T0006.001` Query Platform Metadata APIs, `AML.T0006.002` Scan for Exposed AI Infrastructure, `AML.T0006.003` Probe AI Agent Trigger Channels, `AML.T0129` Triggers in Multimodal Inputs, `AML.T0130` AI Agent Response Biasing, `AML.T0131` Crafted AI Assistant Links, `AML.T0132` Misconfigured or Publicly Exposed AI Services, `AML.T0133` Discover AI Agent Runtime Capabilities, `AML.T0134` AI Targeted Cloaking
- **v2026.10 (+18):** `AML.T0017.003` Malware, `AML.T0085.002` Conversation Context and Memory, `AML.T0085.003` System Instructions, `AML.T0135` Outputs from AI Models, `AML.T0136` Exfiltration via AI User Interface, `AML.T0137` Training Data Information from AI Models, `AML.T0137.000` Infer Membership, `AML.T0137.001` Infer Properties, `AML.T0137.002` Invert AI Model, `AML.T0137.003` Extract Memorized Data, `AML.T0138` Indicator Removal, `AML.T0139` Compromise Accounts, `AML.T0140` Centralized AI Service Request Routing, `AML.T0141` AI Service Request Metadata Sanitization, `AML.T0142` Event Triggered Execution, `AML.T0143` LLM Prompt Propagation, `AML.T0144` Recover AI Model Internals, `AML.T0145` Poison AI Agent Learning Environment

### Removed (moved) [ATLAS-STIX + ATLAS-NOTES + ATLAS-YAML]

ATLAS removes a moved technique from the STIX bundle outright: no `revoked` flag, no `x_mitre_deprecated` flag, and no `revoked-by` relationship (the v2026.10 bundle's relationship types are only `uses`, `mitigates`, `subtechnique-of`, `attributed-to`). Successors therefore come from the release notes, checked against the YAML.

| Removed | v2026.06 name | Successor | Basis |
|---|---|---|---|
| `AML.T0019` | Publish Poisoned Datasets | `AML.T0115.000` Datasets | notes v2026.07 |
| `AML.T0058` | Publish Poisoned Models | `AML.T0115.001` Models | notes print `.000` (typo); sub-ID from YAML |
| `AML.T0104` | Publish Poisoned AI Agent Tool | `AML.T0115.002` AI Agent Tools | notes print `.000` (typo); sub-ID from YAML |
| `AML.T0024.000` | Infer Training Data Membership | `AML.T0137.000` Infer Membership | notes v2026.10 |
| `AML.T0024.001` | Invert AI Model | `AML.T0137.002` Invert AI Model | notes v2026.10 |
| `AML.T0024.002` | Extract AI Model | `AML.T0005.001` Replicate Behavior from Model Outputs (**inferred**) | not in the notes; v2026.10 T0024 text routes extraction to T0005.001 [D] |
| `AML.T0056` | Extract LLM System Prompt | `AML.T0085.003` System Instructions | notes v2026.10 |
| `AML.T0057` | LLM Data Leakage | `AML.T0085.002` Conversation Context and Memory | notes v2026.10 |

### Renamed [ATLAS-STIX]

| ID | v2026.06 | v2026.10 |
|---|---|---|
| `AML.T0005` | Create Proxy AI Model | Replicate AI Model Behavior |
| `AML.T0005.000` | Train Proxy via Gathered AI Artifacts | Replicate Behavior from Gathered AI Artifacts |
| `AML.T0005.001` | Train Proxy via Replication | Replicate Behavior from Model Outputs |
| `AML.T0005.002` | Use Pre-Trained Model | Adapt Existing Model to Replicate Behavior |
| `AML.T0010` | AI Supply Chain Compromise | Supply Chain Compromise |
| `AML.T0010.001` | AI Software | Software |
| `AML.T0010.002` | Data | Data Repository |
| `AML.T0010.003` | Model | Model Repository |
| `AML.T0020` | Poison Training Data | Training Data Poisoning |
| `AML.T0072` | Reverse Shell | Cyber Communication Channel |
| `AML.T0075` | Cloud Service Discovery | Enterprise Resource Discovery |
| `AML.T0089` | Process Discovery | Enterprise Environment Discovery |

Tactic `AML.TA0001` was renamed "AI Attack Staging" → "AI Attack Adaptation" in v2026.08 [ATLAS-NOTES]. D3FEND's class `:ATLASAIAttackStagingTechnique` (the parent named in #608's context line) will likely be renamed by the next ingest, depending on how `update_atlas.py` derives tactic class names.

### Definition text changed [ATLAS-STIX]

68 IDs: `AML.T0000`, `.000.001`, `.000.002`, `T0002`, `.002.002`, `T0005`, `.005.000`, `.005.001`, `.005.002`, `T0006`, `T0008.002`, `.008.004`, `.008.005`, `T0010`, `.010.001`, `.010.002`, `.010.003`, `.010.005`, `T0011`, `.011.000`, `.011.001`, `.011.002`, `.011.003`, `T0013`, `T0014`, `T0016.002`, `T0017`, `T0018`, `T0020`, `T0021`, `T0024`, `T0035`, `T0043`, `.043.002`, `T0044`, `T0048.004`, `T0051`, `.051.001`, `T0052.000`, `T0053`, `T0054`, `T0060`, `T0061`, `T0063`, `T0065`, `T0067.000`, `T0068`, `T0071`, `T0072`, `T0073`, `T0074`, `T0075`, `T0077`, `T0079`, `T0080`, `.080.000`, `T0085`, `.085.000`, `.085.001`, `T0086`, `T0089`, `T0091.001`, `T0095`, `T0099`, `T0100`, `T0102`, `T0109`, `T0110`.

Impact on the crosswalk queue (from `03_rebaseline_check.py`): 55 queued techniques have changed text. **45 rows across 39 techniques** carry a quote that is no longer a verbatim substring of the v2026.10 text, and these must be re-quoted when D3FEND next bumps ATLAS. That count is from the pre-adjudication queue; after the REBASELINE revisions the number is 41 (`crosswalk-rebaseline-2026-11.csv`). Of the 11 PR bodies opened on d3fend-ontology (#607–#619), only #619's quote drifts, and only by a hyphen ("adversary controlled server" → "adversary-controlled server"). #609's quote survives the T0010.001 rename.

### Release-notes defects [ATLAS-NOTES vs ATLAS-YAML]

- The v2026.07 notes list `AML.T0115.000` three times (for Datasets, Models and AI Agent Tools). The data uses `.000/.001/.002`.
- The v2026.07 notes link `AML.AML.T0010.005`, with the prefix doubled.
- The v2026.08 notes call Autonomous Exploit Development "Develop Capabilities … `AML.T0016.001`". The data has it as `AML.T0017.001`, and `AML.T0016.003` (Exploits) goes unlisted.
- The v2026.10 notes omit the removal of `AML.T0024.002` Extract AI Model altogether.

### ATLAS → ATT&CK references [ATLAS-YAML × ATTACK-STIX]

v2026.06 carries 37 `attack-reference`s. One of them is stale: AML.T0073 → T1656, which ATT&CK revoked in favor of T1684.001 on 2026-04-14 (v19, so before v20; v20 revoked no Enterprise technique). v2026.10 carries 48 references, and **none of them is stale** (ATLAS already repointed T0073 to T1684.001). So there is no ATT&CK- or ATLAS-side reference defect to contribute.

## 2. ATT&CK v20 (as ingested on D3FEND develop, #708, 2026-10-15) [D3F-DEV + ATTACK-STIX]

- `ATTACK_VERSION ?= 20.0` on develop. Bundle: 867 Enterprise attack-patterns, 149 revoked and 12 deprecated.
- Baseline 12e2762 → develop: **18 ATT&CK classes added** (`T0869.001/.002`, `T1608.007`, `T1685.007`, `T1696`, `.001/.002`, `T1697`–`T1700`, `T1701`, `.001`–`.006`) and **0 removed**. Newly deprecated on develop relative to the July baseline: `T0807`, `T0853` (ICS), and `T1656` (revoked by `T1684.001` in ATT&CK v19 on 2026-04-14, not in v20).
- **19 ATT&CK techniques gained restrictions**, all in the d3fend-wall cache, and none lost any. These are the maintainers' Sept mapping PRs #667–#681: T1046, T1069, T1129, T1135, T1495, T1547.012/.013/.014, T1553.005/.006, T1564.010/.011/.012/.014, T1612, T1647, T1652, T1654, T1667. Any cache of D3FEND's ATT&CK→artifact mappings built before mid-September predates them.
- **Crosswalk impact.** The ATT&CK-inheritance seeds were re-checked with the same subtree+ancestor method that built them (`scripts/02_attack_seed_drift.py <baseline.ttl> <develop.ttl> data/attack_seed-2026-07.json`). Only T1656 moved, and its ATLAS row (T0073) was `attack-unmapped`, so **no inherited crosswalk row changes**. One seed pair predates develop: AML.T0078 ← T1189 `produces OutboundInternetNetworkTraffic`, which develop asserts as `produces InternetNetworkTraffic` (#631). No queued row uses it.
- Calibration signal from the maintainers' own v20 work: `T1046 Network Service Discovery` was mapped `enumerates ServiceApplicationProcess` + `produces NetworkTraffic`.

## 3. D3FEND develop since the July baseline (12e2762 → a24ebcc) [D3F-DEV]

- **Releases:** 1.5.0 (tagged 2026-08-03, changelog dated 07-31) and 1.6.0 (2026-08-31). develop now carries ATT&CK v20 (#708) unreleased.
- **ATLAS ingest:** unchanged since #611. `ATLAS_VERSION := 2026.06` and 173 ATLAS technique classes, so develop is **four ATLAS releases behind**. No ATLAS bump PR is open as of 2026-11-02. `src/util/update_atlas.py` deprecates only on `revoked` / `x_mitre_deprecated`. ATLAS sets neither for moved techniques, so the next bump would leave the 8 removed IDs as live classes with stale v2026.06 definitions and no pointer to their successor.
- **ATLAS restrictions merged:** #618 (T0037, 09-23) and #617 (T0021, 10-08).
- **New classes (32), none AI/ML/agent:** SPARTA (`DE-0003.13`, `EX-0010.05`, `IMP-0007…0014`), ATT&CK (the 18 above), `Real-timeClock`, `Software-definedRadioWaveformApplicationConfigurationEvent`, `…LoadEvent`, and `WirelessCommand` (#522). **No `MachineLearningEvent` family, no AI model, dataset, prompt, tool or agent artifact, and none of the proposed residual or Kirillov MVP v2 names** exist on develop. The only `MachineLearning` class is the older defensive-KB `d3f:MachineLearning`.
- **Event / agent plumbing:** #647/#648 (1.6.0) materialize restrictions on `d3f:Event` and `d3f:Agent` subclasses as object properties in the build. If Medina's `MachineLearningEvent` family lands under `d3f:Event`, its restrictions will reach the built outputs and the dashboard without further tooling work.
- **Hygiene that matters for PRs:** #631 replaced two undeclared fillers (`InternetWebNetworkTraffic`) that caused an OWL 2 DL profile violation. The maintainers fix undeclared classes, and they would catch one in a contribution.
- **Renamed artifact that hit the queue:** `d3f:NetworkService` → `d3f:NetworkServiceApplicationProcess` in #543 (authored 2026-05-13, in 1.5.0). The July gate validated against the 1.4.0 JSON-LD cache and passed the dead IRI on the queued `AML.T0006 enumerates NetworkService` row. The 2026-11 ground truth now comes from develop source (`data/develop-2026-11/`): **922 artifacts, 199 verbs**.
- **Artifact count:** 915 (1.4.0 cache) → 922 non-deprecated `d3f:Artifact` descendants on develop.

The moved-technique gap is filed upstream as [mitre-atlas/atlas-data#33](https://github.com/mitre-atlas/atlas-data/issues/33).
