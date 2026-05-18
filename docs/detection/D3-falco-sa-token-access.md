# D3: Falco ServiceAccount Token File Access

## Purpose

D3 detects ingress-nginx runtime access to the mounted Kubernetes ServiceAccount token file. This is the runtime signal for the CVE-2025-1974 `auth-snippet include` path reaching the token file.

## Applied File

- `monitoring/falco-rules.yaml`

## Rule

```text
CVE-2025-1974 Nginx Reads ServiceAccount Token
```

## Core Condition

The strict D3 condition is fd-path based:

```yaml
(open_read or open_write) and
fd.name = "/var/run/secrets/kubernetes.io/serviceaccount/token" and
proc.name in (nginx, nginx-ingress-co) and
k8s.ns.name = ingress-nginx
```

The alert output includes only metadata fields:

```text
pod, namespace, proc, file, cmdline, user
```

It must not print or store token/JWT/Bearer/Secret values.

## Reproduction

Apply the Falco rule through Helm custom rules:

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
```

Keep port-forward open:

```bash
kubectl port-forward svc/ingress-nginx-controller-admission 8443:443 -n ingress-nginx
```

Trigger only the ServiceAccount token file path:

```bash
python3 poc/cve_2025_1974_poc.py \
  --target https://127.0.0.1:8443 \
  --step 3 \
  --file /var/run/secrets/kubernetes.io/serviceaccount/token
```

Check the Falco alert:

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --since=10m \
  | grep "CVE-2025-1974 Nginx Reads ServiceAccount Token"
```

## Detection Result

Observed result in `cve-2025-1974-repro-lab`:

- Token-only PoC attempts: 8
- D3 strict alerts: 5
- Successful alert fields:
  - rule: `CVE-2025-1974 Nginx Reads ServiceAccount Token`
  - proc: `nginx`
  - file: `/var/run/secrets/kubernetes.io/serviceaccount/token`
  - namespace: `ingress-nginx`
  - pod: ingress-nginx controller pod

The PoC confirmed file access on every attempt, but Falco alerts were not emitted for every attempt.

## Limitations

- D3 depends on Falco fd path enrichment.
- With `modern_ebpf`, short-lived `nginx -t` config-test processes can sometimes produce file descriptor resolution failures.
- When path enrichment fails, Falco may log:

```text
[libs]: Unable to determine path for file descriptor
```

- In that state, the exploit can still reach the token file while the strict D3 alert is missed.
- Reproduction is more reliable when:
  - Falco is freshly rolled out and given 30-60 seconds to stabilize.
  - port-forward is kept open across repeated attempts.
  - only the token file is targeted with `--step 3 --file`.

## Safe Handling

The PoC can expose token file content in the webhook response. During detection validation, filter output and never print, save, or commit token/JWT/Bearer/Secret values.
