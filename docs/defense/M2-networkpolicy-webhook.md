Restrict ingress-nginx admission webhook target access via NetworkPolicy (M2)

---

# PR Description

## Motivation

- Block direct in-cluster access from attacker Pods to the ingress-nginx admission webhook controller Pod target port `8443`.
- Preserve normal ingress data-plane traffic on ports `80`, `443`, and health endpoint `10254`.
- Provide reproducible and environment-aware validation steps, especially CIDR tuning for Calico/minikube environments.

---

## Description

Updated `defense/m2-networkpolicy.yaml` to enforce M2 webhook access control on ingress-nginx controller Pods.

### Main Changes

- Restricts ingress to port `8443` using `ipBlock.cidr`, which should be set to the control-plane/node CIDR.
- Keeps ports `80`, `443`, and `10254` available for normal ingress-nginx controller operation.
- Adds mitigation tracking labels:
  - `mitigation: m2-networkpolicy`
  - `cve: cve-2025-1974`

---

## Added Documentation

Added `docs/defense/M2-networkpolicy-webhook.md`.

### Documentation Includes

- Calico profile prerequisite and setup context.
- CIDR selection guidance using:
  - `kubectl get nodes -o wide`
  - `minikube ip`
- Baseline vs post-policy verification commands using an in-cluster test Pod with `curl`.
- Safe Ingress creation check to confirm that the kube-apiserver admission path remains functional.
- Optional attacker-Pod verification and cleanup steps.

---

## Testing

Applied the policy with:

```bash
make defense-m2
