# D2/D3 Detection Handoff

## Context

- Target context: `cve-2025-1974-repro-lab`
- Scope: current repro cluster only. Do not modify the older `cve-2025-1974-lab` profile.
- Sensitive data handling: do not print or save token/JWT/Bearer/Secret values.
- Commit hygiene: exclude `results/` and raw logs. Do not run `git add`, `git commit`, or `git push` during verification.

## D2 Summary

D2 detects malicious Ingress requests that pass through the Kubernetes API server. It does not detect direct admission webhook POST traffic.

- Applied files:
  - `monitoring/gatekeeper-template.yaml`
  - `monitoring/gatekeeper-constraint.yaml`
- ConstraintTemplate: `blocknginxdangerousannotations`
- Constraint: `block-dangerous-nginx-annotations`
- Enforcement mode used for detection: `warn`
- Core detection target:
  - `nginx.ingress.kubernetes.io/auth-snippet`
  - `nginx.ingress.kubernetes.io/server-snippet`
  - `nginx.ingress.kubernetes.io/configuration-snippet`
- Core blocked patterns:
  - `include `
  - `/etc/passwd`
  - `/var/run/secrets/`
  - `/proc/self/`
  - `load_module`
  - `.so`

Reproduction command:

```bash
make detect-gatekeeper
make detect-gatekeeper-policy
make attack-enum
make detect-gatekeeper-violations
kubectl get ingress -A
```

Observed result:

- Gatekeeper warning was produced for a kube-apiserver-mediated malicious Ingress request.
- The warning matched `auth-snippet` containing `include ` and `/etc/passwd`.
- The ingress-nginx admission webhook then rejected the request with an nginx parse error.
- No malicious Ingress object remained in the cluster.

Limitations:

- Gatekeeper only sees kube-apiserver admission requests.
- Direct webhook POST used by the CVE-2025-1974 exploit path bypasses Gatekeeper.
- In `warn` mode, Gatekeeper warns but does not block; in this repro, ingress-nginx admission rejected the object later.

## D3 Summary

D3 detects the ingress-nginx `nginx` process opening the mounted ServiceAccount token file.

- Applied file:
  - `monitoring/falco-rules.yaml`
- Rule:
  - `CVE-2025-1974 Nginx Reads ServiceAccount Token`
- Core condition:

```yaml
(open_read or open_write) and
fd.name = "/var/run/secrets/kubernetes.io/serviceaccount/token" and
proc.name in (nginx, nginx-ingress-co) and
k8s.ns.name = ingress-nginx
```

Reproduction command:

```bash
helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --set driver.kind=modern_ebpf \
  --set falco.json_output=true \
  --set falco.log_level=info \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set-file 'customRules.cve-2025-1974\.yaml=monitoring/falco-rules.yaml' \
  --wait \
  --timeout 5m

kubectl rollout status daemonset/falco -n falco --timeout=180s
sleep 45

kubectl port-forward svc/ingress-nginx-controller-admission 8443:443 -n ingress-nginx

python3 poc/cve_2025_1974_poc.py \
  --target https://127.0.0.1:8443 \
  --step 3 \
  --file /var/run/secrets/kubernetes.io/serviceaccount/token
```

Observed result:

- Token-only PoC was run 8 times.
- The exploit path reached the ServiceAccount token file 8 times.
- Falco produced the D3 strict alert 5 times.
- Alert fields observed:
  - rule: `CVE-2025-1974 Nginx Reads ServiceAccount Token`
  - proc: `nginx`
  - file: `/var/run/secrets/kubernetes.io/serviceaccount/token`
  - namespace: `ingress-nginx`

Limitations:

- D3 is sensitive to Falco fd path enrichment.
- Some attempts may miss the alert even when the exploit reaches the file.
- Logs may show `[libs]: Unable to determine path for file descriptor` when Falco cannot resolve the fd path.

## Upload Checklist

Commit candidates:

- `monitoring/falco-rules.yaml`
- `monitoring/gatekeeper-template.yaml`
- `monitoring/gatekeeper-constraint.yaml`
- `docs/detection/HANDOFF-D2-D3.md`
- `docs/detection/D2-gatekeeper-ingress-annotation.md`
- `docs/detection/D3-falco-sa-token-access.md`

Exclude:

- `results/`
- raw `kubectl logs` captures
- token/JWT/Bearer/Secret material

Recommended branch:

```text
detection/d2-d3-handoff
```
