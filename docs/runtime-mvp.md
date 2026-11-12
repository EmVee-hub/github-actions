# Runtime cloud findings → BOD/EPSS — integration pilot

**Status:** an implemented, testable correlation-and-policy slice. The synthetic
AKS/EKS/ECS integration passed CI, but **real customer-cloud runtime coverage has
not yet been validated**. This is an MVP candidate rather than production sign-off.

## End-to-end flow

1. The existing Azure Defender and AWS Inspector collectors preserve raw
   provider findings and provisional normalized vulnerability observations.
2. A read-only Kubernetes Pod or ECS task snapshot identifies *RUNNING*
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

**States:** EVALUATED, SUPPRESSED_BY_VEX, REVIEW_REQUIRED, or NOT_EVALUATED.
Preliminary BOD priorities can be shown under REVIEW_REQUIRED, but these are
not accepted remediation dispositions. A VEX statement is not trusted merely
because it passes syntax and scope checks. Real suppression needs approval
and provenance controls.

Neither a zero-result scan nor a missing runtime correlation proves safety.
No containers are stopped or modified. There is no production gate, due-date
ledger, 95% disposition KPI, or auto-enforcement yet.

## Run the synthetic three-platform integration

From the central github-actions repository root:

~~~bash
FIX=tests/fixtures/runtime
mkdir -p /tmp/runtime-demo
python3 scripts/runtime_workloads.py --platform EKS --cluster eks-demo \
  --account-id 123456789012 --region eu-north-1 \
  --input "$FIX/eks-pods.json" --output /tmp/runtime-demo/eks.json
python3 scripts/runtime_workloads.py --platform ECS --cluster ecs-demo \
  --account-id 123456789012 --region eu-north-1 \
  --input "$FIX/ecs-tasks.json" --output /tmp/runtime-demo/ecs.json
python3 scripts/runtime_workloads.py --platform AKS --cluster aks-demo \
  --subscription-id 11111111-1111-1111-1111-111111111111 \
  --input "$FIX/aks-pods.json" --output /tmp/runtime-demo/aks.json

python3 scripts/runtime_assess.py \
  --inspector "$FIX/inspector-normalized.json" \
  --defender "$FIX/defender-observations.json" \
  --inventory /tmp/runtime-demo/{eks,ecs,aks}.json \
  --cves-only /tmp/runtime-demo/cves.json

# Fixture intelligence is deliberately SYNTHETIC, not the current live feed.
python3 scripts/runtime_assess.py \
  --inspector "$FIX/inspector-normalized.json" \
  --defender "$FIX/defender-observations.json" \
  --inventory /tmp/runtime-demo/{eks,ecs,aks}.json \
  --intel "$FIX/intelligence.json" --vex-map "$FIX/vex-map.json" \
  --output /tmp/runtime-demo/assessment.json \
  --markdown /tmp/runtime-demo/assessment.md
~~~

Expected: 2 EKS/ECS evaluated runtime findings, 1 synthetic AKS VEX
suppression, 1 ECR digest with no running workload match, and 1 Defender
observation lacking digest identity. Those last two remain NOT_EVALUATED.
The GitHub workflow runtime-demo.yml runs the same integration.

## Private GitHub Actions pilot template

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

## Real AWS ECS pilot — run in a PRIVATE execution environment

**Do not upload real cloud inventory, package lists or security findings to
these public source repositories.** Use a private GitHub Actions execution repo
or an approved isolated runner with OIDC and restricted artifact access.

Permissions for the authorised AWS account/Region: Inspector2 ListFindings
and ListCoverage; ECS ListTasks, DescribeTasks, and task tag read where
necessary; STS GetCallerIdentity. Configure one read-only authenticated role,
the ECS cluster name and Region. Inspector enhanced ECR scanning must be
enabled for the target image.

~~~bash
export AWS_ACCOUNT_ID=YOUR_12_DIGIT_ACCOUNT
export AWS_REGION=eu-north-1
export ECS_CLUSTER=YOUR_ECS_CLUSTER

python3 scripts/collect_inspector.py --region "$AWS_REGION" \
  --output /tmp/live-inspector
python3 scripts/runtime_workloads.py --platform ECS --cluster "$ECS_CLUSTER" \
  --account-id "$AWS_ACCOUNT_ID" --region "$AWS_REGION" \
  --output /tmp/live-ecs.json

# The inventory-scoped CVE selection excludes unmatched registry-only images.
python3 scripts/runtime_assess.py \
  --inspector /tmp/live-inspector/normalized-findings.json \
  --inventory /tmp/live-ecs.json --cves-only /tmp/live-cves.json
python3 scripts/fetch_runtime_intel.py \
  --cves /tmp/live-cves.json --output /tmp/live-intelligence.json

# Operator-approved JSON map, project label -> project repo OpenVEX path.
python3 scripts/runtime_assess.py \
  --inspector /tmp/live-inspector/normalized-findings.json \
  --inventory /tmp/live-ecs.json --intel /tmp/live-intelligence.json \
  --vex-map /private/config/project-vex-map.json \
  --output /tmp/live-decisions.json --markdown /tmp/live-report.md
~~~

The metadata keys used for inventory ownership and policy are MVP-specific
conventions: security.example.com/project, security.example.com/exposure, and
security.example.com/prod-critical. They must be set and reviewed in the
workload deployment process; the collector **does not infer** public exposure
or production criticality from cluster topology.

For EKS, use an authorised AWS role with EKS DescribeCluster and Kubernetes
cluster authorization to list Pods across the intended namespaces:

~~~bash
aws eks update-kubeconfig --region "$AWS_REGION" --name YOUR_EKS_CLUSTER
python3 scripts/runtime_workloads.py --platform EKS --cluster YOUR_EKS_CLUSTER \
  --account-id "$AWS_ACCOUNT_ID" --region "$AWS_REGION" \
  --output /tmp/live-eks.json
~~~

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
  immutable digest to an observed RUNNING EKS/ECS container. The Inspector
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

**MVP acceptance should require:** a real private ECS pilot where ECR
digest matches are verified against running tasks; a second EKS/AKS pilot;
source coverage and freshness checks; validated Defender image identity;
operator-approved VEX; and a persistent triage/disposition store.

## References

- AWS ECS DescribeTasks: https://docs.aws.amazon.com/cli/latest/reference/ecs/describe-tasks.html
- AWS Inspector ECR: https://docs.aws.amazon.com/inspector/latest/user/scanning-ecr.html
- Defender containers: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-usage
- FIRST EPSS API: https://api.first.org/epss/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CERTCC decision tables: https://github.com/CERTCC/SSVC
