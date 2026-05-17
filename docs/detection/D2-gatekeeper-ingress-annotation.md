# D2: Gatekeeper Ingress Annotation Detection

## Purpose

D2 detects malicious Ingress objects submitted through the Kubernetes API server. The signal is dangerous nginx annotation content, especially `auth-snippet` using `include`.

This is not a direct webhook POST detector. Direct admission webhook traffic bypasses kube-apiserver admission policy and should be covered by Falco D1/D3 or other runtime telemetry.

## Applied Files

- `monitoring/gatekeeper-template.yaml`
- `monitoring/gatekeeper-constraint.yaml`

## Rules

- ConstraintTemplate: `blocknginxdangerousannotations`
- Constraint kind: `BlockNginxDangerousAnnotations`
- Constraint name: `block-dangerous-nginx-annotations`
- Enforcement action: `warn`

## Core Condition

The template checks dangerous content in these annotation keys:

```text
nginx.ingress.kubernetes.io/auth-snippet
nginx.ingress.kubernetes.io/server-snippet
nginx.ingress.kubernetes.io/configuration-snippet
```

The effective blocked patterns include:

```text
include 
/etc/passwd
/var/run/secrets/
/proc/self/
load_module
.so
```

## Reproduction

Apply Gatekeeper and the D2 policy:

```bash
make detect-gatekeeper
make detect-gatekeeper-policy
```

Trigger D2 through kube-apiserver:

```bash
make attack-enum
```

Check warnings and constraint status:

```bash
make detect-gatekeeper-violations
kubectl get blocknginxdangerousannotations -A
kubectl describe blocknginxdangerousannotations block-dangerous-nginx-annotations
```

Confirm no malicious Ingress remains:

```bash
kubectl get ingress -A
```

## Detection Result

Observed D2 behavior:

- A kube-apiserver-mediated malicious Ingress request was submitted.
- Gatekeeper emitted warnings for `auth-snippet`.
- The matched content included:
  - `/etc/passwd`
  - `include `
- ingress-nginx admission then rejected the object with an nginx parse error.
- The malicious Ingress object did not remain in the cluster.

## Limitations

- D2 only sees API-server admission traffic.
- Direct webhook POST does not create a kube-apiserver admission request and is not visible to Gatekeeper.
- In `warn` mode, Gatekeeper does not block; it only reports the policy hit.
- If another admission controller rejects the object after Gatekeeper warns, persisted Gatekeeper audit violations may show `0` because no object remains for audit.

## Safe Handling

Do not store raw admission payloads if they contain sensitive material. For this D2 case, the tested path was `/etc/passwd`; no token/JWT/Bearer/Secret value should be printed or saved.
