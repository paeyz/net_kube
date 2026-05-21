#!/usr/bin/env bash
# M1 — Webhook Disabled Mitigation
#
# admission webhook을 비활성화하여 direct POST 공격 경로를 제거한다.
#
# 방어 의미:
#   - CVE-2025-1974 공격의 direct admission webhook POST 대상인
#     ingress-nginx admission webhook을 삭제한다.
#
# 한계:
#   - ingress-nginx 자체 admission validation도 꺼진다.
#   - 운영 환경의 장기 방어책으로는 부적합하다.
#   - 실습/비상 완화 또는 M1 효과 검증 목적으로 사용한다.
#
# 사용법:
#   bash defense/m1-webhook-disable.sh apply
#   bash defense/m1-webhook-disable.sh restore
#   bash defense/m1-webhook-disable.sh status
#
# 환경 변수로 override 가능:
#   WEBHOOK_NAME
#   RELEASE_NAME
#   NAMESPACE
#   INGRESS_CHART_VERSION
#   INGRESS_CONTROLLER_VERSION
#   INGRESS_DIGEST

set -euo pipefail

ACTION="${1:-apply}"

WEBHOOK_NAME="${WEBHOOK_NAME:-ingress-nginx-admission}"
RELEASE_NAME="${RELEASE_NAME:-ingress-nginx}"
NAMESPACE="${NAMESPACE:-ingress-nginx}"

# Keep these aligned with scripts/bootstrap_stage2.sh.
INGRESS_CHART_VERSION="${INGRESS_CHART_VERSION:-4.11.3}"
INGRESS_CONTROLLER_VERSION="${INGRESS_CONTROLLER_VERSION:-v1.11.3}"
INGRESS_DIGEST="${INGRESS_DIGEST:-sha256:d56f135b6462cfc476447cfe564b83a45e8bb7da2774963b00d12161112270b7}"

info() {
  echo "[M1] $*"
}

warn() {
  echo "[M1][WARN] $*"
}

error() {
  echo "[M1][ERROR] $*" >&2
}

webhook_exists() {
  kubectl get validatingwebhookconfiguration "$WEBHOOK_NAME" >/dev/null 2>&1
}

confirm_webhook_absent() {
  if webhook_exists; then
    error "webhook still exists: $WEBHOOK_NAME"
    kubectl get validatingwebhookconfiguration "$WEBHOOK_NAME" || true
    exit 1
  fi

  info "confirmed: $WEBHOOK_NAME is not present"
}

confirm_webhook_present() {
  if ! webhook_exists; then
    error "webhook is not present: $WEBHOOK_NAME"
    exit 1
  fi

  kubectl get validatingwebhookconfiguration "$WEBHOOK_NAME"
  info "confirmed: $WEBHOOK_NAME is present"
}

show_status() {
  info "kubectl context: $(kubectl config current-context 2>/dev/null || echo unknown)"

  if webhook_exists; then
    info "webhook status: present"
    kubectl get validatingwebhookconfiguration "$WEBHOOK_NAME"
  else
    warn "webhook status: absent"
  fi

  if kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
    info "ingress-nginx pods:"
    kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/component=controller -o wide || true

    info "admission service:"
    kubectl get svc -n "$NAMESPACE" ingress-nginx-controller-admission 2>/dev/null || true
  else
    warn "namespace not found: $NAMESPACE"
  fi
}

case "$ACTION" in
  apply)
    info "disabling ingress-nginx admission webhook..."
    warn "This removes ingress-nginx admission validation."
    warn "Use this as a lab/emergency mitigation, not as a long-term production control."

    kubectl delete validatingwebhookconfiguration "$WEBHOOK_NAME" --ignore-not-found
    confirm_webhook_absent

    info "done — direct admission webhook POST target removed"
    info "verify: kubectl get validatingwebhookconfiguration $WEBHOOK_NAME should return NotFound"
    info "optional attack validation: make attack-chain should fail to reach the admission webhook"
    ;;

  restore)
    info "restoring ingress-nginx admission webhook through Helm..."
    info "release=$RELEASE_NAME namespace=$NAMESPACE chart=$INGRESS_CHART_VERSION controller=$INGRESS_CONTROLLER_VERSION"

    if ! helm status "$RELEASE_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
      error "Helm release not found: $RELEASE_NAME in namespace $NAMESPACE"
      error "Restore ingress-nginx using the original bootstrap/install method first."
      exit 1
    fi

    helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx 2>/dev/null || true
    helm repo update

    helm upgrade "$RELEASE_NAME" ingress-nginx/ingress-nginx \
      --namespace "$NAMESPACE" \
      --version "$INGRESS_CHART_VERSION" \
      --set controller.image.tag="$INGRESS_CONTROLLER_VERSION" \
      --set controller.image.digest="$INGRESS_DIGEST" \
      --set controller.admissionWebhooks.enabled=true \
      --set controller.admissionWebhooks.failurePolicy=Fail \
      --set controller.service.type=NodePort \
      --set-string controller.config.allow-snippet-annotations=true \
      --wait \
      --timeout 5m

    kubectl rollout status deployment/ingress-nginx-controller -n "$NAMESPACE" --timeout=120s
    confirm_webhook_present

    info "restore complete"
    ;;

  status)
    show_status
    ;;

  *)
    echo "Usage: $0 [apply|restore|status]"
    exit 1
    ;;
esac
