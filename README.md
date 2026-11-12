# github-actions — Grype / OpenVEX / BOD+EPSS CI starter

This repository contains the **CI security action**, the versioned decision policy,
unit tests, and an Azure Defender evidence-collection MVP.

## Azure Defender collector

See [Azure setup and limitations](docs/azure-defender.md) for the scheduled/manual
OIDC workflow, subscription configuration, and output contract. This first slice
collects individual assessments; runtime correlation, OpenVEX matching, and policy
evaluation remain unimplemented for Azure. It does not issue an admission verdict.

## Action: `actions/grype-policy-scan`

Prerequisites in the calling job:

- Linux runner with Python 3.10+, Docker (or another Grype-supported image source) and Grype CLI.
- Source and `vex/openvex.json` checked out.
- The candidate image built locally in the same job.
- Network access to refresh Grype's vulnerability DB.
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
5. Compute BOD 26-04 outcomes using local defaults and CVSS v3 Technical Impact heuristic.
6. Apply the local EPSS quartile amplifier and the KEV / 3D / 3DF guards.
7. Produce Grype JSON, decision JSON and Markdown summary.
8. In `shadow` mode, report blocking policy decisions without failing. In `enforce`, fail unless decision is `ALLOW`.

### Policy and safety limits

- The BOD table is a semantic copy of the 16 outcomes of `cisa:DT_BOD2604:1.0.0`, **not the original repository's schema**.
- `Automatable` always defaults to `Y` in this MVP; Vulnrichment ADP lookup is **not implemented**.
- Technical Impact: `T` only when a usable CVSS v3 vector contains both `C:H` and `I:H`; otherwise `P` for known C/I or conservative `T` if unavailable. It is a **local heuristic**.
- `KEV=Y` if Grype has nonempty `knownExploited`. If the ID maps to a CVE but no KEV annotation is present, `KEV=N` is **provisional** based on Grype's database, not independently validated against the live CISA catalog. If there is no CVE mapping, `KEV=UNKNOWN` and the action reports `REVIEW_REQUIRED`.
- Missing EPSS is neutral Q2 with source recorded.
- This uses policy evaluation only; it does **not** validate that an exposure declaration matches actual networking.
- OpenVEX statements must be reviewed before being accepted; the sanity check doesn't validate signatures, scope or whether technical justifications are true.
- The action intentionally does **not** implement a direct Vulnrichment API, VEX attestation verification, exposure inventory or production image digest promotion. Those are important gaps before broad production enforcement.
- A `3DF` finding requires incident/forensic follow-up. A blocked CI candidate alone is not proof of existing compromise.

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

1. Replace the calling workflow's `YOUR_ORG` and `REPLACE_WITH_FULL_COMMIT_SHA` values.
2. Pin Anchore's Grype downloader action by its audited immutable SHA, and pin Grype itself.
3. Run the action in `shadow` mode across representative images.
4. Validate Grype JSON compatibility with the exact installed Grype version and representative GHSA/CVE matches.
5. Review effects of default `Publicly Exposed=Y`, `Automatable=Y`, and CVSS-based TI.
6. Define a safe way to change `mode` to `enforce`, with monitored failure behavior.
7. Implement a promotion step that verifies the evaluated image is the immutable image digest being deployed.

Upstream references:

- [CERTCC/SSVC BOD 26-04 decision table](https://github.com/CERTCC/SSVC/blob/main/data/json/decision_tables/cisa/cisa_bod_26_04_1_0_0.json)
- [Grype VEX and filtering](https://oss.anchore.com/docs/guides/vulnerability/filter-results/)
- [Grype JSON schema and formats](https://oss.anchore.com/docs/reference/grype/json/)
- [GitHub composite actions](https://docs.github.com/en/actions/tutorials/create-actions/create-a-composite-action)

