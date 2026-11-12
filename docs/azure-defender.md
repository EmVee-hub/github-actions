# Defender for Cloud GitHub Actions starter

First implementation slice for the central `github-actions` repository. This is a tested **evidence collector**, not a completed runtime vulnerability evaluator or deployment gate. No Azure resources are modified.

## What runs

Daily at 04:23 UTC and on manual dispatch: GitHub OIDC → Azure login → Resource Graph individual assessments → raw JSON + provisional CVE observations + collection summary → workflow artifact in a private repository. Public repositories skip artifact uploads; collected evidence is removed from the runner after the job. Use a private execution repository or the local CLI to retain real tenant evidence. Source code and credential-free unit tests can stay public. The schedule and seven-day artifact retention are editable operational defaults, not remediation policy.

The query deliberately discovers `SoftwareUpdate` and `ServiceUpgrade` assessments across the explicitly configured subscriptions. These categories include other resource classes as well as images and AKS nodes. **The resulting rows are candidates, not confirmed running AKS vulnerabilities.** We retain all statuses and all severities, including unresolved records, for subsequent mapping and reconciliation. The collector does not infer package identity from recommendation text.

Microsoft documents the grouped recommendation deprecation on July 31, 2026. This starter uses individual assessments and the documented `CvesDetails`, `DetectedSoftwareVersions`, and `FixedVersion` fields. It does not depend on the deprecated running-image assessment ID `c609cf0f-71ab-41e9-a3c6-9a1f7fe1b8d5`.

## Install in the central repository

1. Use the files already committed on `feature/azure-defender`. The workflow expects `scripts`, `tests` and `queries` at the repository root. It is a repository-local workflow, not yet a cross-repository `workflow_call` implementation. Scheduled execution uses the default branch; this commit does not merge the workflow into `main`.
2. Create a GitHub environment named `defender-read`. Restrict deployment branches to the trusted default branch.
3. Create an Entra application/service principal or user-assigned managed identity with a federated credential: issuer `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`, subject `repo:YOUR_ORG/YOUR_REPO:environment:defender-read`.
4. Grant read access at each selected subscription. For this discovery pilot, the built-in **Reader** role at those subscription scopes provides consistent read access; it is broader than a final custom security-only role. Do not grant Contributor or Owner. If narrowing RBAC, verify the complete intended resources remain visible: ARG can silently return only resources the identity can read. A successful request is not proof of full coverage.
5. Configure these environment variables in GitHub:

| Variable | Value |
|---|---|
| `AZURE_CLIENT_ID` | Federated identity client UUID |
| `AZURE_TENANT_ID` | Entra tenant UUID |
| `AZURE_SUBSCRIPTION_ID` | One selected subscription for Azure login |
| `AZURE_SUBSCRIPTION_IDS` | JSON array, e.g. `["11111111-1111-1111-1111-111111111111"]` |

6. Ensure Defender container/node assessment prerequisites are enabled on the pilot AKS environment. This workflow reads existing provider results; it cannot force a fresh scan.
7. Review and pin the three action references to approved full commit SHAs before production deployment. Version tags are left visible in this starter; no unverified SHA is fabricated.
8. Run manually, inspect `summary.json` and raw assessments, and compare sample records to the Defender portal's **Open query** output. Only enable ongoing use after this comparison.

The default runner is GitHub-hosted Ubuntu to make the starter runnable without your runner labels. For your self-hosted setup, change `runs-on` to a dedicated Linux runner with Python 3.10+ and Azure CLI installed, outbound Azure/GitHub access, and isolated jobs. Keep this credentialed collection workflow off pull-request triggers. The Azure login action handles session cleanup.

## Output contract

| File | Meaning |
|---|---|
| `<subscription>.raw.json` | Complete returned assessment rows, unchanged |
| `observations.json` | One provisional observation per assessment/CVE; not deduplicated affected instances |
| `unresolved.json` | Assessment IDs whose CVE payload cannot be interpreted |
| `query.json` | Exact query and API version used |
| `summary.json` | Fetch timestamp, counts, resource types, collection and evaluation status |

`collection_status=COMPLETE` means all configured queries completed with validated pagination. It does **not** mean scan coverage or risk evaluation is complete. `runtime_coverage=UNKNOWN` and `policy_evaluation=NOT_EVALUATED` remain explicit. A zero-row result cannot establish that workloads are safe or even scanned. The collection timestamp is not a scan timestamp; provider timestamps remain in raw data.

Unknown image digest, PURL, runtime relevance and criticality remain null. Every provisional observation has `decision=INCOMPLETE` and `vex_status=NOT_EVALUATED`. Keep this staging schema separate from the final common finding schema. Do not suppress findings or feed these observations into production admission as successful evaluations.

Failed collection exits nonzero and writes an incomplete summary; files already captured from earlier subscriptions remain partial evidence until upload/cleanup (private execution) or local inspection (CLI). No automatic retry is performed: retry the job after investigating transient failures. The collector refuses an existing output directory to prevent stale evidence being mistaken for a new run.

## Next integration slice

Use a sanitized real container and node assessment from this run to implement and test the provider-specific resource/package mapping. Then:

- Reconcile immutable image digest and architecture against running AKS workload inventory, and node VM IDs against AKS node pools. Keep image and node findings separate.
- Add authoritative prod-critical classification and coverage/freshness evidence. Do not calculate the 95% KPI until its denominator is known.
- Match project-owned OpenVEX by product/component identity; unmatched or ambiguous assertions cannot suppress findings.
- Adapt these observations to the shared BOD 26-04 + EPSS evaluator. The current `scripts/evaluate.py` accepts Grype input, so this collector does not call it directly. Record 3D/3DF runtime findings for remediation/forensic triage; do not automatically stop workloads.
- Persist first/last seen and disposition history outside short-lived workflow artifacts.

Runtime threat alerts (malware, anomalous execution, compromise) require a separate alert/incident ingestion path. They are not converted into CVE observations by this collector.

## Local validation

### Offline debug: paste data instead of fetching Azure

No Azure CLI, credentials, OIDC, or subscription environment variables are needed.
Both modes use the same normalization function. Offline output is explicitly marked
`mode: DEBUG_OFFLINE`; it cannot establish runtime coverage or a policy verdict.

Run the bundled synthetic example from the repository root:

```bash
python3 scripts/read_azure.py --input tests/fixtures/defender-sample.json --out /tmp/defender-debug-1
```

Or save your JSON as a file and pass `--input your-data.json`. To paste directly:

```bash
python3 scripts/read_azure.py --input - --out /tmp/defender-debug-2 <<'JSON'
[{"id":"demo-assessment","subscriptionId":"11111111-1111-1111-1111-111111111111","properties":{"metadata":{"severity":"Critical"},"status":{"code":"Unhealthy"},"additionalData":{"CvesDetails":[{"CveId":"CVE-2021-44228"}],"DetectedSoftwareVersions":["2.14.1"]}}}]
JSON
```

Accepted shapes: a raw assessment object, an array of assessments, or an ARG response
with a `data` array. Truncated ARG responses and duplicate IDs fail explicitly. Missing
CVE details are retained in `unresolved.json`. Use a fresh output directory each time.

Inspect `summary.json`, `observations.json`, `unresolved.json`, and `input.raw.json`.
The bundled example produces two assessments, one CVE observation, and one unresolved
assessment. Its data is illustrative, not a captured provider response.

For GitHub UI use, `.github/workflows/defender-debug.yml` adds **Defender offline debug**:
select **Run workflow**, select the branch, and paste JSON into `assessment_json`.
Leaving it blank uses the bundled example. This workflow has no Azure login or OIDC
permission. It uploads debug output and shows counts in the run summary. **Use only
synthetic/sanitized input in this public repository**: inputs and output artifacts
are not a confidential channel. Real tenant data can be tested with the local CLI.

GitHub requires a manually dispatched workflow to exist on the default branch before
it is available for dispatch. Until this new workflow is merged into `main`, use the
local commands above; committing on the feature branch does not enable that UI yet.

This debug path tests parsing/normalization, not VEX matching or BOD/EPSS decisions.

```bash
python3 -m unittest discover -s tests -v
# After az login, using a NEW output directory:
export AZURE_SUBSCRIPTION_IDS='["YOUR-SUBSCRIPTION-UUID"]'
python3 scripts/read_azure.py --out output
```

Tests cover continuation tokens, truncation, duplicate pages, subscription boundaries, malformed CVE payloads, unknown identity and invalid configuration. No live tenant validation has been performed.

## Primary references (reviewed November 11, 2026)

- [Individual recommendation migration and field mappings](https://learn.microsoft.com/en-us/azure/defender-for-cloud/transition-grouped-individual-recommendations)
- [Review recommendations and generate tenant-specific queries](https://learn.microsoft.com/en-us/azure/defender-for-cloud/review-security-recommendations)
- [Resource Graph REST request/response and pagination](https://learn.microsoft.com/en-us/rest/api/azureresourcegraph/resourcegraph/resources/resources?view=rest-azureresourcegraph-resourcegraph-2024-04-01)
- [Resource Graph permissions and partial visibility](https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview)
- [Defender container scanning prerequisites and limitations](https://learn.microsoft.com/en-us/azure/defender-for-cloud/agentless-vulnerability-assessment-azure)
- [Azure Login OIDC configuration](https://github.com/Azure/login)
