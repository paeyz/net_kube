# D1 Webhook Direct Access Detection Handoff

## Overview

This document hands off the D1 detection for the CVE-2025-1974 IngressNightmare lab.

D1 detects direct network access from an in-cluster pod to the ingress-nginx admission webhook. In normal Kubernetes operation, admission webhook calls should be made by the Kubernetes API server. A workload pod directly connecting to the ingress-nginx admission webhook is suspicious and matches the attack path used in this lab.

## Detection Purpose

Detect attacker-controlled pods that directly connect to the ingress-nginx admission webhook service.

The detection is intended to identify the early network access stage of the CVE-2025-1974 attack chain before or during exploitation attempts against the admission webhook.

## Detection Target

- Source: workload pod in the `default` namespace
- Process: attacker process inside the pod, observed as `python3`
- Destination service: `ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local`
- Destination ClusterIP: `10.100.193.38`
- Destination port: `443`
- Related endpoint observed in this lab: `10.244.0.33:8443`

Known successful detection example:

```text
pod=attacker-pod
namespace=default
process=python3
connection=10.244.0.62:55236 -> 10.100.193.38:443
command=python3 poc/attack_chain.py --target https://ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local:443 --out /attack/results
```

Do not store JWT tokens, Kubernetes service account tokens, Authorization headers, cookies, or raw secrets in evidence files. Replace them with `<REDACTED>`.

## Falco Rule

- Rule name: `CVE-2025-1974 Webhook Direct Access`
- Priority: `Critical`
- Tags: `cve-2025-1974`, `d1`, `network`, `webhook`
- Rule file: `monitoring/falco-rules.yaml`
- Loaded path in Falco Pod: `/etc/falco/rules.d/falco_rules.local.yaml`

The Falco custom rule is applied through the Falco Helm chart `customRules` mechanism. The rule must be mounted into the Falco Pod, not only created as a standalone ConfigMap.

## Reproduction Procedure

From the project root:

```bash
cd ~/network_sec/net_kube
```

Confirm Falco custom rules are applied:

```bash
make detect-falco-rules
```

Run the attacker chain:

```bash
kubectl run attacker-pod --rm -i \
  --restart=Never \
  --image=cve-2025-1974-attacker:latest \
  --image-pull-policy=Never \
  --command -- python3 poc/attack_chain.py \
  --target https://ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local:443 \
  --out /attack/results
```

If a shorter connectivity-only test is needed:

```bash
kubectl run d1-test --rm -i \
  --restart=Never \
  --image=cve-2025-1974-attacker:latest \
  --image-pull-policy=Never \
  --command -- python3 -c "import socket; s=socket.create_connection(('ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local',443),5); print('connected'); s.close()"
```

## Detection Verification Commands

Follow Falco logs:

```bash
make detect-falco-logs
```

Or query the current Falco Pod directly:

```bash
FALCO_POD=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n falco "$FALCO_POD" -c falco --since=10m | grep "CVE-2025-1974 Webhook Direct Access"
```

Confirm the custom rule file is mounted and loaded:

```bash
kubectl exec -n falco "$FALCO_POD" -c falco -- ls -la /etc/falco/rules.d
kubectl logs -n falco "$FALCO_POD" -c falco --since=10m | grep "/etc/falco/rules.d/falco_rules.local.yaml"
```

## Success Criteria

D1 is considered successful when Falco emits a Critical event with:

- `rule`: `CVE-2025-1974 Webhook Direct Access`
- `priority`: `Critical`
- `k8s.pod.name`: `attacker-pod`
- `k8s.ns.name`: `default`
- `proc.name`: `python3`
- destination connection to `10.100.193.38:443`
- tags containing `cve-2025-1974`, `d1`, `network`, and `webhook`

Save redacted evidence under:

```text
evidence/d1/falco-d1-detected-redacted.log
```

Before committing evidence, inspect it and replace any sensitive values with `<REDACTED>`.

## Evidence Handling

Recommended evidence command:

```bash
FALCO_POD=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n falco "$FALCO_POD" -c falco --since=10m \
  | grep "CVE-2025-1974 Webhook Direct Access" \
  > evidence/d1/falco-d1-detected-redacted.log
```

After saving the log, manually review the file. Redact secrets before sharing or committing:

```text
Authorization: Bearer <REDACTED>
token=<REDACTED>
jwt=<REDACTED>
```

## Notes And Cautions

- Do not run destructive cleanup commands such as `minikube delete`, `make clean`, or `kubectl delete namespace`.
- Do not modify D4 documentation or D4 rules as part of D1 handoff.
- Do not assume a ConfigMap alone means Falco loaded the rule. Confirm the rule exists under `/etc/falco/rules.d` in the Falco Pod.
- If the ingress-nginx admission Service ClusterIP or endpoint changes, update the D1 IP list in `monitoring/falco-rules.yaml` and re-run `make detect-falco-rules`.
- Store only redacted evidence in `evidence/d1/`.
