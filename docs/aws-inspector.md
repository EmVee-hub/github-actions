# AWS Inspector GitHub workflow — first implementation

This starter implements the AWS **collection and normalization** part of our
runtime workflow. The files are integrated into `github-actions`. It does not yet
implement project OpenVEX, BOD 26-04 or EPSS percentile evaluation, and must not
be used as a deployment security gate. A green job means collection succeeded.

## Included

- Manually triggered workflow, one job per configured AWS Region.
- GitHub OIDC role authentication; no static AWS access keys.
- AWS CLI service pagination for findings and scan coverage.
- Original findings, scan coverage, normalized package observations and manifest.
- Read-only IAM permissions and environment-scoped trust policy example.
- Nine offline tests covering pagination, failures and normalization boundaries.

## Setup

1. Enable Inspector for relevant ECR images and EC2 instances. Configure relevant
   ECR repositories for continuous enhanced scanning for EKS/ECS image mapping.
   Check supported Regions, scan eligibility and coverage before interpreting results.
2. Create/reuse the GitHub OIDC identity provider in the AWS account. Create a role
   with `iam/aws-inspector/read-policy.json` and the edited trust-policy example. Replace
   `ACCOUNT_ID` and `YOUR_ORG`; keep the repository/environment restriction exact.
3. Create GitHub environment `aws-security-read`; restrict deployment branches to
   your trusted default branch. The trust subject is environment-based, so branch
   restriction must be enforced by the environment configuration.
4. Set repository variable `AWS_INSPECTOR_REGIONS` to your JSON Region array.
   Set environment variables `AWS_INSPECTOR_ROLE_ARN` and `AWS_ACCOUNT_ID` to the
   role ARN and expected 12-digit account ID. These are GitHub configuration
   variables, not long-lived credentials. Example Region: `["eu-north-1"]`.
5. Use a trusted Linux self-hosted runner with Python 3.10+, AWS CLI v2 and a
   current Actions runner compatible with the actions' Node runtimes. Allow
   GitHub/OIDC/artifact and AWS STS/Inspector network access. Do not use a runner
   shared with untrusted pull-request code.
6. Review and pin the
   action version tags to verified commit SHAs before production rollout. Version
   tags are used in this starter; no SHA has been invented.
7. After merging this workflow into the default branch, dispatch `AWS Inspector collection`. GitHub requires a manually dispatched workflow to exist on the default branch. Inspect
   the manifest and coverage artifact as well as the findings. Only enable a
   schedule after validating a real account run.

The initial workflow targets one role/account, across explicit Regions. A
delegated administrator can receive member-account findings; each observation
retains its owning account. Additional accounts need explicit role/account matrix
configuration. This starter does not create cloud resources or enable paid scans.

## Run and test locally

```bash
python3 -m unittest discover -s tests -v
python3 scripts/collect_inspector.py --region eu-north-1 --output ./report
```

The output directory must not already exist. This prevents accidentally mixing a
new incomplete collection with previous successful output. Authentication uses
the normal AWS CLI credential chain when run locally.

## Output contract

| File | Meaning |
|---|---|
| `manifest.json` | Collection timing, caller account, counts and completion flag |
| `raw-findings.json` | All returned finding types/statuses, unchanged |
| `coverage.json` | Inspector covered resources and their scan status |
| `normalized-findings.json` | One observation per ECR/EC2 package/resource pair |

Normalized fields deliberately leave KEV, production criticality and EPSS
percentile null. Inspector exploit availability does not prove CISA KEV
membership; its EPSS probability is not a percentile. Missing packages are
retained as an empty package for later data-quality handling. Other resource and
finding types remain available in raw evidence but are not normalized here.

The observation ID retains provider identity, account, Region, resource,
digest/architecture, vulnerability and package path/version details. It is not
a cross-scanner canonical affected-instance ID. Cross-source deduplication and
PURL derivation belong in the shared normalization layer after identity validation.

## Runtime and policy boundaries

- `REPORTED_IN_USE` means Inspector reports a positive image-use count; it does
  not identify the specific workload or prove current production-critical use.
- Zero and absent image-use metadata remain distinct. Mapping is asynchronous;
  neither a zero count nor a missing finding proves a workload is safe.
- All statuses are collected: provider suppression is not VEX evidence, and
  CLOSED is not automatically FIXED_VERIFIED.
- EC2 host observations require an inventory join to identify EKS nodes/ECS hosts.
  Fargate underlying hosts are not customer EC2 assets.
- Empty findings and even empty coverage do not establish complete runtime
  coverage. Join inventory, coverage and findings before calculating the 95% KPI.
- Inspector supplies vulnerability observations, not proof of active compromise.
- Artifacts retain data for 14 days as a configurable starter setting; they are
  not the durable disposition ledger required by the full design.

Next integration is: resolve workload/project by immutable image identity → load
that project's VEX → validate applicability → obtain KEV/SSVC/EPSS intelligence
and exposure → invoke the shared pinned decision table and amplifier. Outcomes
remain pending until this exists. No findings are automatically suppressed and
no invented CVSS threshold replaces our policy.

## Validation status

Offline tests run in the supplied workspace. Live AWS authentication, permission
scope, real API responses, GitHub execution and self-hosted runner compatibility
still need an account-backed validation run. This is a reviewable starter, not a
claim of production readiness.

## Primary references

- https://docs.aws.amazon.com/cli/latest/reference/inspector2/list-findings.html
- https://docs.aws.amazon.com/cli/latest/reference/inspector2/list-coverage.html
- https://docs.aws.amazon.com/inspector/v2/APIReference/API_AwsEcrContainerImageDetails.html
- https://docs.aws.amazon.com/inspector/latest/user/scanning-ecr.html
- https://github.com/aws-actions/configure-aws-credentials

## Offline debug: insert data instead of pulling from AWS

From the repository root, use Python only — no AWS CLI, credentials, account
variables, environment approval, or network access is needed for normalization:

```bash
python3 scripts/collect_inspector.py \
  --input-file tests/fixtures/inspector-debug.json \
  --output ./inspector-debug-report
```

Copy the fixture and edit the `findings` array to insert your own data. It uses
Inspector's `list-findings` response shape: `{"findings": [...]}`. Saved
`raw-findings.json` reports can also be replayed. Empty arrays are valid. Inputs
with pagination tokens are rejected: combine all pages before replay.

You can pipe JSON directly:

```bash
printf '%s' '{"findings": []}' | python3 scripts/collect_inspector.py \
  --input-file - --output ./empty-debug-report
```

Optionally pass `--coverage-file coverage.json` with a `coveredResources` array.
Without it, coverage is empty and `coverage_supplied` is false, not evidence of
full scan coverage. Use a new output directory for each run. Malformed JSON or
normalization failures exit nonzero and leave `collection_complete: false`.

In GitHub Actions, choose **AWS Inspector collection → Run workflow → mode:
debug**. Paste JSON into **findings_json**, or leave it blank to use the synthetic
fixture. Debug uses a GitHub-hosted runner with contents-read permission only.
Choose **aws** explicitly for the live collection path and its existing setup.
The workflow must first exist on the default branch for manual dispatch to be
available in GitHub; the local command works immediately on this feature branch.

Artifacts are named `inspector-debug-*`. The manifest and normalized rows record
`input_mode: offline`; the manifest has `live_aws_data: false`. The synthetic
samples illustrate Critical/Medium/Low/Informational source severities and
positive/zero/missing usage metadata. They do **not** simulate BOD outcomes:
VEX, intelligence enrichment and decision evaluation remain pending.

Avoid pasting confidential inventory into a public repository or public workflow
run. Use local replay for sensitive real exports.
