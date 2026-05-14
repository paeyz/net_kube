# D1/D4 Detection Handoff

## Summary

This branch contains D1 and D4 detection handoff materials for the CVE-2025-1974 lab.

## D1 - Webhook Direct Access

D1 detects direct access from a container to the ingress-nginx admission webhook.

- Main detector: Falco
- Rule: CVE-2025-1974 Webhook Direct Access
- Evidence: evidence/d1/falco-d1.log
- Status: Detected successfully

D1 direct webhook access does not pass through kube-apiserver, so Kubernetes Audit Log is not the primary detector for this behavior.

## D4 - Kubernetes API Lateral Movement

D4 checks Kubernetes API access by the ingress-nginx ServiceAccount.

- Main detector: Kubernetes Audit Log
- Policy: monitoring/audit-policy.yaml
- Evidence: evidence/d4/audit-d4-filtered.json
- Current evidence 1: secrets watch event by `system:serviceaccount:ingress-nginx:ingress-nginx`
- Current evidence 2: kube-system secrets list event generated through Kubernetes impersonation
- Additional evidence: `evidence/d4/audit-d4-kubesystem-secrets-list-redacted.json`

Additional D4 verification:
A kube-system secrets list request was generated using Kubernetes impersonation with `--as=system:serviceaccount:ingress-nginx:ingress-nginx`. The request was recorded in Kubernetes Audit Log with `verb=list`, `resource=secrets`, `namespace=kube-system`, and `responseStatus.code=200`.

Important note:
This verifies that the Audit Log policy can capture D4-style kube-system secrets list behavior. However, this was an impersonation-based verification, not a stolen-token reproduction.


## Useful Commands

```bash
make detect-falco-rules
make detect-audit
make detect-falco-logs
make detect-audit-tail


