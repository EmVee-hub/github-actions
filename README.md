# github-actions — Grype / OpenVEX / BOD+EPSS CI starter

This repository contains the **CI security action**, the versioned decision policy,
and Azure Defender / AWS Inspector evidence-collection MVPs with independent tests.

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

## AWS Inspector runtime collection

The initial AWS collector uses OIDC to read Inspector findings and scan coverage
across configured Regions, preserves raw evidence, and normalizes ECR/EC2 package
observations. See [AWS setup and limitations](docs/aws-inspector.md).

This collection workflow does not yet apply project VEX or the decision policy.
A successful collection is not a deployment admission decision.


## Azure Defender runtime collection

See [Azure setup and offline debug](docs/azure-defender.md). The collector retains
individual assessments and provisional CVE observations. Runtime correlation, VEX
matching and policy evaluation remain pending for Azure.

## Independent CI workflows

| Workflow | Tests | Triggered by |
|---|---|---|
| `ci-defender.yml` — Defender CI | `test_read_azure.py` | Defender collector, query, fixtures, docs and workflows |
| `ci-aws.yml` — AWS CI | `test_inspector.py` | Inspector collector, IAM, fixtures, docs and workflows |
| `ci-policy.yml` — Policy CI | `test_evaluate.py` | Shared policy, Grype action, evaluator and fixtures |

Each workflow supports manual dispatch and uses path filters for pushes and pull
requests. A provider-only change does not trigger the other provider's CI. None
of these CI workflows logs in to a cloud or collects live findings. The runtime
collection workflows also run only their respective provider tests.

The old `test.yml` workflow is replaced. If branch protection requires its old
check, update that configuration before merging. Path-filtered workflows should
not be unconditional required checks: a skipped workflow may leave such a check
pending. No branch-protection settings are changed here.
