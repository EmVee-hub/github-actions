# Defender for Containers — running AKS Pods only

**Scope:** vulnerabilities in container images actually used by running AKS Pods. Excluded: Azure VMs, Kubernetes node OS, generic SoftwareUpdate/ServiceUpgrade findings and unused container registry images.

## Collector restrictions

`queries/assessments.kql` and `scripts/read_azure.py` now restrict candidate assessments to explicit `resourceDetails.ResourceType` values (`k8s-container`, `.containerImage`, `container-image`, case-insensitive). Unknown/non-container resource types are excluded rather than guessed. This avoids mixing host/node remediation with container image vulnerability prioritisation.

**Coverage warning:** Microsoft's Defender container findings may be delivered as **subassessments**, and actual type names/payloads must be validated against the current tenant. Our allowlist is conservative and has only synthetic verification. Therefore zero observations from this query **does not mean** AKS images are safe or even fully scanned. This is a remaining live-validation blocker.

The runtime evaluator requires confirmed RUNNING Pod status, subscription, registry/repository and immutable image digest. Defender records missing digest/package identity remain outside the active running-container CVE report, with aggregate exclusion counts. Do not fill missing identities from CVE text or image tags.

The manual public `poc-showcase.yml` uses **synthetic Defender fixtures only**. The previous scheduled `defender-cloud.yml` collection is retired. For a future operational MVP, use a **private** read-only OIDC/AKS RBAC pilot; never upload sensitive tenant data in the public source repo. See `docs/runtime-poc.md` and `examples/private-execution/runtime-pilot.yml`.

## Offline tests

~~~bash
python3 -m unittest discover -s tests -p 'test_read_azure.py' -v
python3 scripts/read_azure.py --input tests/fixtures/defender-sample.json --out /tmp/defender-container-debug
~~~

Reference: https://learn.microsoft.com/en-us/azure/defender-for-cloud/resource-graph-samples
