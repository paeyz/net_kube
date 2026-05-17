# D1/D4 Detection Summary

## PoC Reproduction

PoC reproduction succeeded on minikube profile `cve-2025-1974-lab-new`.

The attacker pod reached the ingress-nginx admission webhook and completed the attack chain. Token extraction and Kubernetes API lateral movement were observed in the attack output.

## D1 Result

D1 succeeded only with the manual stable validation procedure.

The full attack-chain run proved direct webhook access in the attacker logs, but it did not reliably produce the Falco D1 alert because the attacker pod started and exited quickly.

Evidence:

- `results/detection/sanitized/d1_attack_retry3.log`
- `results/detection/sanitized/d1_falco_retry.log`
- `results/detection/sanitized/d1_falco_raw_retry3.log`
- `results/detection/sanitized/d1_falco_filtered_retry.log`

Key alert:

```text
CVE-2025-1974 Webhook Direct Access
```

## D1 Failure Cause

- Original D1 Falco rule was centered on `8443`.
- Actual direct target in this lab was the admission Service on `443`.
- Falco used `rule_matching: first`.
- The full attack-chain pod timing made startup-time webhook connect events unreliable for D1 alerting.

## D1 Manual Validation Procedure

1. Apply and confirm the Falco rule.
2. Keep `attacker-pod` Running/Ready.
3. From inside the pod, connect to `ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local:443`.
4. Send a direct webhook TCP connect/POST.
5. Confirm `CVE-2025-1974 Webhook Direct Access` in Falco logs.
6. Store raw, filtered, and final D1 logs under `results/detection/`.

Observed environment values for this run:

- Service DNS: `ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local`
- Service ClusterIP: `10.98.129.52`
- Controller endpoint: `10.244.0.7:8443`
- Manual D1 attacker pod IP: `10.244.0.33`

These are experiment values, not portable defaults.

## D4 Result

D4 succeeded with the full attacker chain.

Evidence:

- `results/detection/sanitized/d4_attack.log`
- `results/detection/sanitized/d4_falco.log`
- `results/detection/sanitized/d4_audit.log`
- `results/detection/sanitized/attacker_logs.log`

Observed D4 evidence:

- Attack log shows token extraction and Kubernetes API lateral movement.
- Falco shows `CVE-2025-1974 kubectl in Container`.
- Audit Log shows `system:serviceaccount:default:attacker-sa` using `kubectl/v1.30.8` against Kubernetes API resources.

## Remaining Limits

- D1 is not yet a reliable full attack-chain automatic detection.
- A dedicated D1 validation target is needed.
- Sanitized logs are committed; original local logs may contain sensitive token material and should not be pushed.

## Defense Team Handoff

- Treat D4 as full attack-chain detection success.
- Treat D1 as manual stable validation success.
- Do not claim that D1 is automatically stable in the full attack chain.
- Re-check ClusterIP/PodIP values in any new lab environment.
