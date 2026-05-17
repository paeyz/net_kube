# D1/D4 Detection Handoff

## Purpose

This handoff summarizes the local CVE-2025-1974 IngressNightmare detection validation so the defense team can continue from the same Git branch without repeating the full investigation.

The lab was run only on the minikube profile `cve-2025-1974-lab-new`. The existing `cve-2025-1974-lab` profile was not deleted or reused for this validation.

## Scope

- D1: Falco detection for direct access from an attacker pod to the ingress-nginx admission webhook.
- D4: Falco and Kubernetes Audit Log detection for token use and Kubernetes API lateral movement.
- D2/Gatekeeper validation is out of scope for this handoff.

## Environment Values

These values are from this specific local run and should not be treated as portable defaults:

- minikube profile: `cve-2025-1974-lab-new`
- admission service: `ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local:443`
- observed admission service ClusterIP: `10.98.129.52`
- observed ingress-nginx controller pod endpoint: `10.244.0.7:8443`
- observed D1 manual validation attacker pod IP: `10.244.0.33`
- observed D4 attacker pod IP: `10.244.0.27`

## D4 Result

D4 succeeded with the full attacker chain.

The attack log shows token extraction and Kubernetes API lateral movement activity. Falco detected `CVE-2025-1974 kubectl in Container` events from `attacker-pod`. Kubernetes Audit Log also recorded API access by `system:serviceaccount:default:attacker-sa`.

Evidence logs:

- `results/detection/sanitized/d4_attack.log`
- `results/detection/sanitized/d4_falco.log`
- `results/detection/sanitized/d4_audit.log`
- `results/detection/sanitized/attacker_logs.log`

Sensitive token material was masked in the committed sanitized logs.

## D1 Initial Failure

D1 was initially failed/ambiguous.

Observed causes:

- The original Falco rule focused on port `8443`, while the attacker reached the admission Service on `443`.
- Falco was configured with `rule_matching: first`, so an earlier matching built-in rule could prevent later custom rules from emitting.
- The full attacker chain starts and exits quickly. The webhook direct access happens near container startup, which made Falco/Kubernetes metadata enrichment timing unreliable for this specific D1 alert.

## D1 Rule Updates

The D1 Falco rule was updated to:

- inspect `connect` events from containers,
- consider server port `443` and `8443`,
- match the admission webhook DNS name `ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local`,
- include fd debug output fields: `fd.name`, `fd.sip`, `fd.sip.name`, `fd.sport`, `fd.rip`, `fd.rport`, `fd.lport`, and `proc.name`.

`scripts/setup_falco.sh` was also updated so the custom rule ConfigMap is mounted into the Falco DaemonSet and Falco uses `rule_matching: all`.

The hardcoded IPs observed during the experiment are documented above as environment values, not encoded as portable rule defaults.

## D1 Result

D1 succeeded with a manual stable validation flow.

This is not a full attack-chain automatic detection success. The reliable result came from keeping an attacker pod Running/Ready and then executing a direct TCP connect/POST to the admission webhook from inside that pod.

Evidence logs:

- `results/detection/sanitized/d1_attack_retry3.log`
- `results/detection/sanitized/d1_falco_retry.log`
- `results/detection/sanitized/d1_falco_raw_retry3.log`
- `results/detection/sanitized/d1_falco_filtered_retry.log`

The key Falco alert is `CVE-2025-1974 Webhook Direct Access`.

## D1 Manual Validation Procedure

1. Confirm the Falco custom rules are applied and mounted:

   ```bash
   make detect-falco-rules
   kubectl exec -n falco daemonset/falco -c falco -- grep -n "Webhook Direct Access" /etc/falco/falco_rules.local.yaml
   kubectl exec -n falco daemonset/falco -c falco -- grep -n "rule_matching" /etc/falco/falco.yaml
   ```

2. Keep `attacker-pod` in `Running/Ready` state instead of running the full chain immediately.

3. From inside `attacker-pod`, connect directly to:

   ```text
   ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local:443
   ```

   Send a direct webhook TCP connect/POST from the pod.

4. Check Falco logs for:

   ```text
   CVE-2025-1974 Webhook Direct Access
   ```

5. Save the attack and Falco logs under `results/detection/`. Commit only sanitized logs.

## Defense Team Notes

- Do not treat D1 as a full attack-chain automatic detection success.
- D1 should be reproduced with the manual stable validation procedure above.
- D4 can be treated as a full attacker-chain detection success because the attack log, Falco log, and Audit Log align on time, subject, and Kubernetes API activity.
- ClusterIP and PodIP values in this document are experiment-specific. Re-check them in a new cluster.

## Clone Or Checkout

Fresh clone from the handoff branch:

```bash
git clone -b detection/d1-d4-handoff <내 GitHub net_kube 주소>
cd net_kube
```

Existing repo:

```bash
git remote add yoon <내 GitHub net_kube 주소>
git fetch yoon
git switch detection/d1-d4-handoff
```

## Next Step

Add a dedicated D1 automated validation target that:

- starts a stable attacker pod,
- performs the direct webhook connect/POST from inside the pod,
- waits briefly for Falco,
- stores raw and filtered Falco logs,
- fails clearly if `CVE-2025-1974 Webhook Direct Access` is absent.
