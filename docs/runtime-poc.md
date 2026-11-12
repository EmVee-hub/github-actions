# Runtime cloud findings → BOD/EPSS — integration pilot

**Status:** an implemented, testable correlation-and-policy slice. The synthetic
AKS/EKS integration passed CI, but **real customer-cloud runtime coverage has
not yet been validated**. This is a completed **technical PoC**, not an operational MVP or production sign-off.

## Container-only scope

**Only running AKS/EKS Pod containers count.**
EC2 hosts, VM/node OS, Lambda, unrelated services and non-running ECR/ACR
images are outside the runtime security program. Registry image vulnerability
data is only source evidence after an exact match to a running container.
Unmatched provider observations are excluded from the active finding table,
but an exclusion count is retained to avoid treating missing evidence as safe.

## End-to-end flow

1. The existing Azure Defender and AWS Inspector collectors preserve raw
   provider findings and provisional normalized vulnerability observations.
2. A read-only Kubernetes Pod snapshot identifies *RUNNING*
   containers and their immutable **manifest digests**.
3. The new runtime assessor correlates those identities by digest,
   registry/repository, and account/Region or Azure subscription. An image
   tag, Inspector in-use count, and raw containerd configuration digest do
   **not** prove a running image match.
4. Fetch authoritative and explicitly complete CISA KEV, FIRST EPSS
   **percentile**, and CISA-ADP Vulnrichment SSVC.
5. Apply the same unchanged BOD 26-04 + local EPSS amplifier policy as the
   Grype CI evaluator. The amplifier does not manufacture KEV or 3DF.
6. Load operator-reviewed project VEX from an explicit local project/path
   map. Exact CVE, immutable image product, and versioned package PURL are
   required to consider a not_affected statement for suppression.
7. Emit JSON and Markdown with the provider, workload, project, source
   evidence, VEX status, base/final deadline and explicit evaluation state.

**States for confirmed running containers:** EVALUATED, SUPPRESSED_BY_VEX
or REVIEW_REQUIRED. Unmatched registry/unknown-digest observations are excluded
from the active runtime findings, with exclusion counts kept separately.
Preliminary BOD priorities can be shown under REVIEW_REQUIRED, but these are
not accepted remediation dispositions. A VEX statement is not trusted merely
because it passes syntax and scope checks. Real suppression needs approval
and provenance controls.

Neither a zero-result scan nor a missing runtime correlation proves safety.
No containers are stopped or modified. There is no production gate, due-date
ledger, 95% disposition KPI, or auto-enforcement yet.

## Run the synthetic AKS/EKS Pod integration

From the central github-actions repository root:

~~~bash
FIX=tests/fixtures/runtime
mkdir -p /tmp/runtime-demo
python3 scripts/runtime_workloads.py --platform EKS --cluster eks-demo \
  --account-id 123456789012 --region eu-north-1 \
  --input "$FIX/eks-pods.json" --output /tmp/runtime-demo/eks.json
python3 scripts/runtime_workloads.py --platform AKS --cluster aks-demo \
  --subscription-id 11111111-1111-1111-1111-111111111111 \
  --input "$FIX/aks-pods.json" --output /tmp/runtime-demo/aks.json

python3 scripts/runtime_assess.py \
  --inspector "$FIX/inspector-normalized.json" \
  --defender "$FIX/defender-observations.json" \
  --inventory /tmp/runtime-demo/{eks,aks}.json \
  --cves-only /tmp/runtime-demo/cves.json

# Fixture intelligence is deliberately SYNTHETIC, not the current live feed.
python3 scripts/runtime_assess.py \
  --inspector "$FIX/inspector-normalized.json" \
  --defender "$FIX/defender-observations.json" \
  --inventory /tmp/runtime-demo/{eks,aks}.json \
  --intel "$FIX/intelligence.json" --vex-map "$FIX/vex-map.json" \
  --output /tmp/runtime-demo/assessment.json \
  --markdown /tmp/runtime-demo/assessment.md
~~~

Expected: 2 EKS Pod findings evaluated and 1 synthetic AKS VEX
suppression. An unmatched ECR image and a Defender record with missing digest
are counted as **excluded** rather than shown as running-container CVEs.
The manual GitHub workflow `.github/workflows/poc-showcase.yml` (scenario: `runtime` or `all`) replays the same synthetic integration.

## Private AKS/EKS pilot template — next-phase validation

The completed public PoC does **not** execute live cloud-collection
workflows or scheduled scans. Only synthetic findings are used in the
public `poc-showcase.yml`. The following private pilot is retained as
a **future validation template**, not proof that actual cluster findings
have already been correlated.

Copy [examples/private-execution/runtime-pilot.yml](../examples/private-execution/runtime-pilot.yml)
into the .github/workflows directory of a **private** execution repository.
The workflow deliberately refuses to start in public repositories. Configure
an isolated self-hosted Linux runner, a restricted runtime-security-read GitHub
environment, AWS_RUNTIME_ROLE_ARN/AWS_ACCOUNT_ID (AWS), or Azure federated
identity variables (AKS). For EKS/AKS the role also needs cluster credential
access and Kubernetes RBAC to list the scoped Pods.

It is a manually dispatched, **shadow-only** pilot: it collects provider findings
and running workloads, fetches full KEV plus percentile/SSVC, runs the common
policy and uploads short-lived evidence into the PRIVATE repository only.
It checks out the current service-blueprint OpenVEX by a pinned commit; only
workloads explicitly labeled project=service-blueprint can use that VEX.
Review and update the pinned central toolkit SHA and project SHA when merging.
It does not create cloud resources or automatically change production workloads.

## Real AWS EKS pilot — use a private read-only execution environment

**Do not upload live workload inventory, vulnerability findings or credentials
to these public source repositories.** Use a private execution repository with
an approved isolated runner and read-only federated cloud identity.

Authorize Inspector2 ListFindings/ListCoverage, EKS DescribeCluster and
STS GetCallerIdentity, plus Kubernetes RBAC to list Pods. Inspector ECR
scanning provides CVEs only for images matched to running EKS Pods.

~~~bash
export AWS_ACCOUNT_ID=YOUR_12_DIGIT_ACCOUNT
export AWS_REGION=eu-north-1
export EKS_CLUSTER=YOUR_EKS_CLUSTER
python3 scripts/collect_inspector.py --region "$AWS_REGION" \
  --output /tmp/live-inspector
aws eks update-kubeconfig --region "$AWS_REGION" --name "$EKS_CLUSTER"
python3 scripts/runtime_workloads.py --platform EKS --cluster "$EKS_CLUSTER" \
  --account-id "$AWS_ACCOUNT_ID" --region "$AWS_REGION" \
  --output /tmp/live-eks.json
python3 scripts/runtime_assess.py \
  --inspector /tmp/live-inspector/normalized-findings.json \
  --inventory /tmp/live-eks.json --cves-only /tmp/live-cves.json
python3 scripts/fetch_runtime_intel.py \
  --cves /tmp/live-cves.json --output /tmp/live-intelligence.json
python3 scripts/runtime_assess.py \
  --inspector /tmp/live-inspector/normalized-findings.json \
  --inventory /tmp/live-eks.json --intel /tmp/live-intelligence.json \
  --vex-map /private/config/project-vex-map.json \
  --output /tmp/live-decisions.json --markdown /tmp/live-report.md
~~~

For Pod metadata, this PoC reads these explicit, organization-defined labels:
`security.example.com/project`, `security.example.com/exposure`, and
`security.example.com/prod-critical`. The exporter does not infer actual
Internet exposure or business criticality from cluster networking.

For AKS, the Azure identity needs read access to Defender/Resource Graph,
AKS credential access and Kubernetes RBAC allowing listing the intended Pods:

~~~bash
az aks get-credentials --resource-group YOUR_RG --name YOUR_AKS_CLUSTER
python3 scripts/read_azure.py --out /tmp/live-defender
python3 scripts/runtime_workloads.py --platform AKS --cluster YOUR_AKS_CLUSTER \
  --subscription-id YOUR_AZURE_SUBSCRIPTION_UUID \
  --output /tmp/live-aks.json
~~~

Then use --defender /tmp/live-defender/observations.json, the AKS inventory,
and the same intelligence/policy steps. A generic Defender observation
**usually does not contain the validated manifest digest, repository and
versioned package identity** needed for this join. In that case, the
assessment remains IMAGE_IDENTITY_INCOMPLETE. Extract and verify actual
provider-specific image identity from a **sanitized real assessment** before
claiming production AKS correlation. Do not infer a digest from a CVE or tag.

## Identity safeguards and known gaps

- Kubernetes containerd://sha256 IDs may be **configuration digests**; the
  exporter will not treat them as registry manifest digests unless an
  authoritative image reference includes @sha256. Unknown is recorded.
- AWS ECR image findings require matching account, Region, repository, and
  immutable digest to an observed RUNNING EKS Pod container. The Inspector
  inUseCount field is NOT a workload identifier.
- Azure joins additionally require a matching subscription, registry,
  repository and digest. Missing identity is visible; provider CLOSED or
  SUPPRESSED status does not automatically equal resolved or VEX not_affected.
- Multi-arch/image-index and platform digest differences require validation
  against actual workload/registry metadata; architecture is not enforced yet.
- Package PURLs may be unavailable from the cloud collectors. We never
  invent them; missing component identity requires review before VEX closure.
- The initial mapper supports only exact product URNs of the form
  urn:container:sha256:... plus a versioned subcomponent PURL. VEX signatures
  and trust-chain approval are not yet implemented.
- Inventory must be complete for its requested scope. A successful command
  does NOT prove comprehensive cluster discovery or Inspector/Defender scan
  coverage. Freshness, source coverage, pod/node mapping, and production
  criticality ownership still need operational verification.
- No durable first/last-seen ledger, remediation owner tracking, 3DF incident
  workflow, or 95% prod-critical disposition accounting exists yet.

**Next phase — operational MVP acceptance requires:** a private EKS pilot matching Inspector
image digests to running Pods, a separate AKS pilot, coverage and freshness
validation, verified Defender image identity, approved project VEX and a
persistent triage/disposition store.

## References

- AWS Inspector ECR: https://docs.aws.amazon.com/inspector/latest/user/scanning-ecr.html
- Defender containers: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-usage
- FIRST EPSS API: https://api.first.org/epss/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CERTCC decision tables: https://github.com/CERTCC/SSVC
