## M1: Admission Webhook Disable

M1 removes the ingress-nginx ValidatingWebhookConfiguration named `ingress-nginx-admission`.

Detection link:
- D1 observed direct access to `ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local:443`.
- M1 removes the admission webhook configuration so the direct admission webhook POST path is no longer available.

Validation:
- Before M1: `kubectl get validatingwebhookconfiguration ingress-nginx-admission` returns the webhook.
- Apply: `make defense-m1`.
- After M1: the same kubectl command returns NotFound.
- Restore: `make defense-m1-restore`.
- After restore: the webhook is present again.

Limitations:
- This disables ingress-nginx admission validation.
- This is appropriate for lab/emergency mitigation, not as a long-term production control.
- M2 and M3 provide more targeted controls for network access and kube-apiserver mediated annotation admission.
