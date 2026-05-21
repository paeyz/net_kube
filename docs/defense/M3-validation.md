## M3 validation

Baseline showed that the original M3 policy denied dangerous `auth-snippet`
and `server-snippet` annotations, but did not directly deny
`configuration-snippet` or `/proc/self/` patterns.

Updated M3 now aligns with D2 Gatekeeper detection coverage:
- `auth-snippet`
- `server-snippet`
- `configuration-snippet`

Blocked patterns:
- `include `
- `load_module`
- `/etc/passwd`
- `/var/run/secrets/`
- `/proc/self/`
- `.so`

Validation:
- Dangerous `auth-snippet` denied by VAP.
- Dangerous `server-snippet` denied by VAP.
- Dangerous `configuration-snippet` denied by VAP before ingress-nginx webhook.
- `/proc/self/` pattern denied by VAP.
- Safe Ingress without dangerous annotations is allowed.
