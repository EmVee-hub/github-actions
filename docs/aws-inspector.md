# AWS Inspector — running EKS container images only

**Scope:** vulnerable packages in container images **confirmed running** in EKS Pods. EC2 hosts, VM/node OS, Lambda, generic network findings and unused registry images are out of scope.

## Collector and runtime correlation

The Inspector collector (`scripts/collect_inspector.py`) requests only `AWS_ECR_CONTAINER_IMAGE` resources and `PACKAGE_VULNERABILITY` findings through documented ListFindings filter criteria. Offline input is filtered to the same scope before persistence. The normalized data retains package, digest, Region, account and provider status; it does not turn a registry finding into a running workload finding.

The evaluator (`scripts/runtime_assess.py`) reports a CVE only after matching ECR account, Region, repository and **immutable image digest** to an observed RUNNING EKS Pod container. Inspector `inUseCount` is not reliable proof of running workload identity. Unmatched image findings are excluded from the active runtime table, with aggregate counts retained. A zero-finding result does not establish runtime scan coverage.

The existing `.github/workflows/aws-inspector.yml` reads collection evidence. For an operational pilot, use the **private** `examples/private-execution/runtime-pilot.yml` with read-only OIDC, trusted runners and Kubernetes Pod-list RBAC. Do not upload live AWS findings to this public repository.

Outputs remain `manifest.json`, `raw-findings.json`, `normalized-findings.json`, and `coverage.json`; all retained findings are **ECR container images only**. Registry coverage remains different from running workload coverage. Provider SUPPRESSED does not equal project VEX.

## Offline tests

~~~bash
python3 -m unittest discover -s tests -p 'test_inspector.py' -v
python3 scripts/collect_inspector.py --input-file tests/fixtures/inspector-debug.json --output /tmp/ecr-container-debug
~~~

References: https://docs.aws.amazon.com/cli/latest/reference/inspector2/list-findings.html and https://docs.aws.amazon.com/inspector/latest/user/scanning-ecr.html.
