# D4 Kubernetes API Lateral Movement Detection Handoff

## Overview

This document hands off the D4 detection for the CVE-2025-1974 IngressNightmare lab.

D4 detects post-exploitation activity where an attacker-controlled container uses Kubernetes client tools or direct network connections to query the Kubernetes API Server. This behavior is associated with ServiceAccount token abuse, permission discovery, and lateral movement.

## Detection Purpose

Detect workload containers that attempt to access the Kubernetes API Server from inside the cluster.

The D4 detection covers two related behaviors:

- execution of `kubectl` inside a container
- direct TCP connection from a container process to the Kubernetes API Server at `kubernetes.default.svc:443` or `10.96.0.1:443`

## Detection Target

Representative D4 activity includes:

- `kubectl version`
- `kubectl cluster-info`
- `kubectl get pods`
- `kubectl get serviceaccounts`
- `kubectl get configmaps`
- `kubectl get secrets -A`
- `kubectl auth can-i ...`
- `kubectl --token=<REDACTED_JWT> get pods`
- `kubectl --token=<REDACTED_JWT> get secrets`
- `curl`, `wget`, `python`, or `python3` connecting to `https://kubernetes.default.svc:443`
- any container connection to `10.96.0.1:443`

Do not store JWT tokens, ServiceAccount tokens, Authorization headers, cookies, or raw secrets in evidence. Replace them with `<REDACTED_JWT>` or `<REDACTED>`.

## Related Falco Rules

Custom D4 rules in `monitoring/falco-rules.yaml`:

- `CVE-2025-1974 kubectl in Container`
- `CVE-2025-1974 Container Calls Kubernetes API`

Related built-in Falco rule:

- `Contact K8S API Server From Container`

The custom D4 API connection rule is designed to emit reduced command context. It avoids printing full `%proc.cmdline` because `kubectl --token=...` can expose JWT tokens in Falco logs.

Expected custom D4 output fields:

- rule name
- priority
- pod name
- namespace
- process name
- reduced command, using the process name only
- connection tuple or destination IP/port

## Rule Loading Check

Falco custom rules must be mounted into the Falco Pod through Helm `customRules`.

Confirm the custom rule file is loaded:

```bash
FALCO_POD=$(kubectl get pod -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n falco "$FALCO_POD" -c falco -- find /etc/falco -maxdepth 3 -type f
kubectl logs -n falco "$FALCO_POD" -c falco --since=10m | grep "/etc/falco/rules.d/falco_rules.local.yaml"
```

Expected result:

```text
/etc/falco/rules.d/.../falco_rules.local.yaml
/etc/falco/rules.d/falco_rules.local.yaml | schema validation: ok
```

## Reproduction Procedure

From the project root:

```bash
cd ~/network_sec/net_kube
```

Apply Falco custom rules:

```bash
make detect-falco-rules
```

Run a D4 validation pod:

```bash
kubectl run d4-test --rm -i \
  --restart=Never \
  --image=cve-2025-1974-attacker:latest \
  --image-pull-policy=Never \
  --command -- sh -c 'kubectl version || true; kubectl cluster-info || true; kubectl get pods || true; kubectl get serviceaccounts || true; kubectl get configmaps || true; kubectl auth can-i get secrets -A || true; python3 -c "import socket; s=socket.create_connection((\"kubernetes.default.svc\",443),5); print(\"api-connected\"); s.close()" || true'
```

Optional token-based test:

```bash
kubectl run d4-token-test --rm -i \
  --restart=Never \
  --image=cve-2025-1974-attacker:latest \
  --image-pull-policy=Never \
  --command -- sh -c 'kubectl --token=<REDACTED_JWT> get pods || true'
```

Never paste a real token into documentation, chat, Git commits, or evidence files.

## Detection Verification Commands

Follow Falco logs:

```bash
make detect-falco-logs
```

Or query recent Falco logs directly with JWT redaction:

```bash
FALCO_POD=$(kubectl get pod -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n falco "$FALCO_POD" -c falco --since=10m \
  | grep -Ei "CVE-2025-1974 kubectl in Container|CVE-2025-1974 Container Calls Kubernetes API|Contact K8S API Server From Container|d4-test|kubectl|10.96.0.1|kubernetes.default|auth can-i" \
  | sed -E 's/[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/<REDACTED_JWT>/g'
```

## Success Criteria

D4 is successful when Falco emits at least one event from each custom D4 rule:

```text
rule=CVE-2025-1974 kubectl in Container
priority=Warning
pod=d4-test
ns=default
proc=kubectl
reduced_command=kubectl
```

```text
rule=CVE-2025-1974 Container Calls Kubernetes API
priority=Warning
pod=d4-test
ns=default
proc=kubectl
reduced_command=kubectl
connection=<pod-ip>:<ephemeral-port>->10.96.0.1:443
```

The built-in Falco rule `Contact K8S API Server From Container` can also appear and is useful supporting evidence, but the D4 handoff should prioritize the two CVE-tagged custom rules above.

## Evidence Handling

Evidence directory:

```text
evidence/d4/
```

Recommended redacted evidence filename:

```text
evidence/d4/falco-d4-detected-redacted.log
```

Recommended evidence collection command:

```bash
FALCO_POD=$(kubectl get pod -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n falco "$FALCO_POD" -c falco --since=10m \
  | grep -Ei "CVE-2025-1974 kubectl in Container|CVE-2025-1974 Container Calls Kubernetes API|Contact K8S API Server From Container" \
  | sed -E 's/[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/<REDACTED_JWT>/g' \
  > evidence/d4/falco-d4-detected-redacted.log
```

Before committing evidence, manually inspect it:

```bash
grep -REni "[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}" evidence/d4 docs/detection monitoring scripts
```

The command must return no JWT tokens. If any token appears, replace it with `<REDACTED_JWT>` before committing.

## Defense Team Handoff Points

- D4 is a post-exploitation signal. It indicates that an attacker is trying to use Kubernetes API access from inside a workload container.
- `kubectl in Container` is a process execution signal and should be treated as suspicious in application pods.
- `Container Calls Kubernetes API` is a network signal and catches API access even when the process is not `kubectl`.
- The custom D4 output intentionally avoids full command lines to reduce JWT exposure risk.
- RBAC denial messages still count as D4 activity. The attacker attempted API discovery even if Kubernetes returned `Forbidden`.
- The default Falco rule `Contact K8S API Server From Container` remains useful context, but the CVE-specific D4 rules are the primary handoff evidence.

## Notes And Cautions

- Do not run destructive cleanup commands such as `minikube delete`, `make clean`, or `kubectl delete namespace`.
- Do not commit raw Falco logs containing JWTs, ServiceAccount tokens, Authorization headers, or secret values.
- Do not include `.bak` files or files under `results/` in the D4 PR unless explicitly reviewed and redacted.
- If the Kubernetes API Service IP changes from `10.96.0.1`, update `cve_2025_1974_k8s_api_ips` in `monitoring/falco-rules.yaml` and re-run `make detect-falco-rules`.
- If a real `--token=...` test is required, run it locally only and redact the token from logs before storing evidence.
