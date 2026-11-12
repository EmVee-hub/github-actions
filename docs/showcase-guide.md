# Start here — how to read the showcase

**All results in this workflow are synthetic. No AWS/Azure credentials or live cloud collection are used.**

Selecting **all** runs three independent demonstrations, not one connected collection pipeline:

| Job | What it shows | Input |
|---|---|---|
| AWS Inspector | Provider JSON converted into container/package findings | `tests/fixtures/inspector-debug.json` |
| Azure Defender | CVEs extracted from container assessments, including unresolved records | `tests/fixtures/defender-sample.json` |
| AKS/EKS correlation | Prepared provider observations matched to running Pod images, then VEX + BOD/EPSS | `tests/fixtures/runtime/` |

The provider jobs do **not** supply the combined runtime demo. Their counts and vulnerability IDs are therefore not expected to match. A live end-to-end run still needs validated provider identity and actual Pod inventory.

## Reading the runtime table

| Column / status | Meaning |
|---|---|
| CONFIRMED_RUNNING | Exact image identity matched a running Pod in the supplied inventory; here that inventory is synthetic |
| ACTIVE | Not suppressed by project VEX; this is distinct from the provider's own status |
| SUPPRESSED_BY_VEX | Matching project VEX says not affected; Base/Final remain evidence, **not an active remediation deadline** |
| KEV | Y = listed in the supplied known-exploited catalog |
| PE | Y = public exposure; unknown exposure defaults to public |
| EPSS bin | Percentile quartiles Q1–Q4, not exploitation probability; missing EPSS uses neutral Q2 |
| Base / Final | Original BOD outcome / outcome after the local EPSS amplifier; KEV keeps the base result |
| FSU / 60D / 14D / 3D | Next scheduled major upgrade or rebuild / remediation within the indicated days |
| 3DF | Three-day remediation plus forensic follow-up; not proof of compromise |
| EVALUATED | Priority calculated; does not mean remediated or safe |
| REVIEW_REQUIRED | Evidence is insufficient to complete the decision |

Excluded findings could not be tied to a running image: `IMAGE_IDENTITY_INCOMPLETE` means missing identity; `NO_EXACT_RUNTIME_MATCH` means no exact inventory match. Neither means fixed or clean.

Provider summaries show observations **before** runtime evaluation. Azure's unknown digest/package fields are visible gaps, not zero findings. Inspector usage counts alone do not establish EKS runtime coverage.

No workloads are changed or stopped. Inspect the uploaded JSON artifacts for complete source and identity evidence. Start a **new workflow run** on the updated branch to see changes; rerunning an old run retains its old workflow revision.


## Expected security issues in this synthetic run

A green job means the program ran and its assertions passed; it does not mean zero vulnerabilities. Warning annotations highlight the deliberately affected examples.

| Runtime example | Expected result |
|---|---|
| AWS payments-abc | Active 3D finding after EPSS amplification |
| AWS billing-abc | Active 14D finding; KEV base outcome preserved |
| Azure customer-api-abc | Active 3DF finding, no VEX exception; remediation and forensic follow-up indicated |
| Azure internal-tools-abc | Same CVE, different image/project: suppressed by its exact scoped VEX statement |

The Azure active example uses prepared runtime identity, not an improvement to live Defender identity extraction. Missing-identity and unmatched-image examples remain excluded and counted. The runtime report does not enforce deployment admission or stop workloads.
