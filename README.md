# github-actions — Grype / OpenVEX / BOD+EPSS CI starter

This repository contains the **CI security action**, the versioned decision policy,
and Azure Defender / AWS Inspector evidence-collection PoC code with independent tests.

## Action: `actions/grype-policy-scan`

Prerequisites in the calling job:

- Linux runner with Python 3.10+, Docker (or another Grype-supported image source) and Grype CLI.
- Source and `vex/openvex.json` checked out.
- The candidate image built locally in the same job.
- Network access to refresh Grype's vulnerability DB and to query public CVE Services (`cveawg.mitre.org`).
- Access to the private action repository (if private).

Parameters:

| Input | Values | Default |
|---|---|---|
| `image` | Local image tag/reference | required |
| `vex-path` | OpenVEX JSON path in caller repo | required |
| `exposure` | `public` / `internal` / `unknown` | `unknown` => public |
| `mode` | `shadow` / `enforce` | `shadow` |
| `grype-binary` | Grype CLI path | `grype` |
| `report-directory` | Reports destination | `security-reports` |

Outputs: `admission` (`ALLOW`, `BLOCK`, `REVIEW_REQUIRED`), `report-json`, `report-markdown`.

### What the action does

1. Validate basic OpenVEX document structure. **Not comprehensive JSON Schema validation.**
2. Update the Grype vulnerability DB; fail if unavailable.
3. Scan the image with `--by-cve --vex ... --output json`, using an explicit empty ignore config.
4. Ignore `ignoredMatches` for the gate, but retain them in reports.
5. Look up distinct unsuppressed CVEs in CISA's ADP Vulnrichment data via CVE Services.
6. Compute BOD 26-04 outcomes using published SSVC Automatable and Technical Impact when present; otherwise use our defaults.
7. Apply the local EPSS quartile amplifier and the KEV / 3D / 3DF guards.
8. Produce Grype, Vulnrichment, decision JSON and Markdown summary.
9. In `shadow` mode, report blocking policy decisions without failing. In `enforce`, fail unless decision is `ALLOW`.

### Policy and safety limits

- The BOD table is a semantic copy of the 16 outcomes of `cisa:DT_BOD2604:1.0.0`, **not the original repository's schema**.
- `Automatable` uses the published CISA-ADP SSVC value when available; otherwise defaults to `Y`.
- Technical Impact: prefer CISA-ADP SSVC; otherwise use the **local heuristic** `T` when CVSS v3 has both `C:H` and `I:H`, `P` for other known C/I, or conservative `T` if unavailable.
- `KEV=Y` if Grype has nonempty `knownExploited`. If the ID maps to a CVE but no KEV annotation is present, `KEV=N` is **provisional** based on Grype's database, not independently validated against the live CISA catalog. If there is no CVE mapping, `KEV=UNKNOWN` and the action reports `REVIEW_REQUIRED`.
- Missing EPSS is neutral Q2 with source recorded.
- This uses policy evaluation only; it does **not** validate that an exposure declaration matches actual networking.
- OpenVEX statements must be reviewed before being accepted; the sanity check doesn't validate signatures, scope or whether technical justifications are true.
- CISA SSVC lookup failures (network errors or invalid payload) produce `REVIEW_REQUIRED`, not a silent fallback. No assessment / 404 uses the documented defaults. VEX attestation verification, exposure inventory and production digest promotion remain gaps before enforcement.
- A `3DF` finding requires incident/forensic follow-up. A blocked CI candidate alone is not proof of existing compromise.

## CISA Vulnrichment

The action queries `https://cveawg.mitre.org/api/cve/<CVE-ID>` for each unique CVE in unsuppressed Grype matches. It reads SSVC metrics **only** from the CISA-ADP provider (short name and the published CISA ADP organisation ID). Extracted values and source timestamps are recorded in `security-reports/vulnrichment.json`.

| CISA lookup | Action |
|---|---|
| Found | Use CISA Automatable and Technical Impact |
| No SSVC or 404 | Use the documented local defaults |
| Timeout, HTTP 429/5xx or invalid published SSVC | `REVIEW_REQUIRED` |
| No CVE mapping | `REVIEW_REQUIRED` under existing KEV-UNKNOWN policy |

Do not equate SSVC `Exploitation: none` with `KEV=N`. A CVE lookup is **not** an independent KEV catalog verification.

## Run tests

```bash
python3 -m unittest discover -s tests -v
```

## Test without a live scan

```bash
python3 scripts/evaluate.py \
  --input tests/fixtures/grype-sample.json \
  --policy-dir policy \
  --image demo:build-1 \
  --exposure public \
  --output /tmp/decision.json \
  --markdown /tmp/report.md
```

## Next steps before enforcement

1. Pin the caller to the reviewed commit SHA of `EmVee-hub/github-actions`.
2. Pin Anchore's Grype downloader action by its audited immutable SHA, and pin Grype itself.
3. Run the action in `shadow` mode across representative images.
4. Validate Grype JSON compatibility with the exact installed Grype version and representative GHSA/CVE matches.
5. Review which findings use CISA-supplied SSVC and which use defaults; live API requests still require a runner smoke test.
6. Define a safe way to change `mode` to `enforce`, with monitored failure behavior.
7. Implement a promotion step that verifies the evaluated image is the immutable image digest being deployed.

Upstream references:

- [CERTCC/SSVC BOD 26-04 decision table](https://github.com/CERTCC/SSVC/blob/main/data/json/decision_tables/cisa/cisa_bod_26_04_1_0_0.json)
- [Grype VEX and filtering](https://oss.anchore.com/docs/guides/vulnerability/filter-results/)
- [Grype JSON schema and formats](https://oss.anchore.com/docs/reference/grype/json/)
- [GitHub composite actions](https://docs.github.com/en/actions/tutorials/create-actions/create-a-composite-action)

## Runtime cloud findings → shared BOD/EPSS

See [AKS/EKS running-container correlation PoC](docs/runtime-poc.md).
It implements read-only workload digest inventory, exact AWS Inspector/Defender
finding joins, complete CISA KEV + FIRST EPSS + CISA Vulnrichment lookup,
shared BOD 26-04 + local amplifier, and project-scoped VEX statuses.

The [manual synthetic PoC showcase](.github/workflows/poc-showcase.yml)
passes offline on AKS and EKS Pod fixtures. **Real cloud coverage and identity
verification are not yet completed; particularly Azure Defender digest and
package mapping require sanitized provider evidence.**

## AWS Inspector container evidence — PoC

The Inspector collector script reads ECR container-image package findings
and normalizes them for an EKS Pod correlation check. The public
[`poc-showcase.yml`](.github/workflows/poc-showcase.yml) feeds it **synthetic
Inspector fixtures**; no live AWS account is contacted.

See [Inspector setup, evidence constraints and limitations](docs/aws-inspector.md).
An ECR image finding only becomes part of our runtime CVE assessment after an
exact match to an observed **running EKS Pod image digest**.

## Azure Defender container evidence — PoC

See [Azure setup and offline normalization](docs/azure-defender.md).
The collector produces provisional container findings. AKS Pod digest
correlation, VEX and policy evaluation pass synthetic tests; **live
Defender image/package identity and coverage remain unverified**.

## Workflows — completed technical PoC

This public repository intentionally contains **two** GitHub Actions
workflows:

| Workflow | Trigger | Purpose |
|---|---|---|
| [`ci.yml`](.github/workflows/ci.yml) | Pull requests, main push, manual | Offline policy, Inspector, Defender, AKS/EKS correlation and VEX regression tests; no cloud credentials |
| [`poc-showcase.yml`](.github/workflows/poc-showcase.yml) | Manual only | Choose `all`, `runtime`, `inspector` or `defender`; run synthetic cases and publish demonstration artifacts |

The former `runtime-demo.yml`, `aws-inspector.yml` and
`defender-cloud.yml` workflows have been consolidated/retired.
**The previous scheduled Azure collection and public-repository live AWS/Azure
collection are deliberately disabled**. Nothing in these two workflows
accesses a real cloud account or verifies production workload coverage.

Run the offline provider CLIs locally if required:

```bash
python3 scripts/read_azure.py --input tests/fixtures/defender-sample.json --out /tmp/defender-poc
python3 scripts/collect_inspector.py --input-file tests/fixtures/inspector-debug.json --output /tmp/inspector-poc
```

A separate [private execution template](examples/private-execution/runtime-pilot.yml)
documents how a future **operational MVP pilot** could test real AKS/EKS
identity and policy decisions under read-only OIDC and Kubernetes RBAC.
Do **not** upload live security findings into this public repository.

**PoC conclusion:** the CI and synthetic correlation pipeline demonstrates
technical feasibility. Live-cloud coverage, approved VEX provenance, policy
calibration, dispositions and enforcement remain MVP work.

