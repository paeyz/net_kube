#!/usr/bin/env bash
# Detection/Defense Team — OPA/Gatekeeper 설치 + D2 정책 적용
#
# 사용법: bash scripts/setup_gatekeeper.sh [install|policy|violations|uninstall]
#
# 참고: https://open-policy-agent.github.io/gatekeeper/website/docs/install/

set -euo pipefail

GK_NS="gatekeeper-system"
TEMPLATE_FILE="$(dirname "$0")/../monitoring/gatekeeper-template.yaml"
CONSTRAINT_FILE="$(dirname "$0")/../monitoring/gatekeeper-constraint.yaml"

_check_helm() {
  if ! command -v helm &>/dev/null; then
    echo "[ERROR] helm이 필요합니다"
    exit 1
  fi
}

cmd_install() {
  _check_helm
  echo "[Gatekeeper] Helm repo 추가..."
  helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
  helm repo update

  echo "[Gatekeeper] OPA/Gatekeeper 설치..."
  helm upgrade --install gatekeeper gatekeeper/gatekeeper \
    --namespace "$GK_NS" --create-namespace \
    --wait --timeout 5m

  echo "[Gatekeeper] 설치 완료"
  kubectl get pods -n "$GK_NS"

  # 정책 적용
  cmd_policy
}

cmd_policy() {
  echo "[Gatekeeper] CVE-2025-1974 D2 정책 적용..."

  # ConstraintTemplate 먼저 적용
  kubectl apply -f "$TEMPLATE_FILE"
  echo "  ConstraintTemplate 적용됨"

  # CRD 등록 대기 (최대 30초)
  echo "  CRD 등록 대기..."
  for i in $(seq 1 15); do
    if kubectl get crd blocknginxdangerousannotations.constraints.gatekeeper.sh &>/dev/null; then
      break
    fi
    sleep 2
  done

  # Constraint 적용 (warn 모드)
  kubectl apply -f "$CONSTRAINT_FILE"
  echo "  Constraint 적용됨 (enforcementAction: warn)"
  echo ""
  echo "  탐지 모드 전환:"
  echo "    warn → deny: monitoring/gatekeeper-constraint.yaml의 enforcementAction을 'deny'로 변경 후 재적용"
}

cmd_violations() {
  echo "=== OPA/Gatekeeper Violations ==="
  kubectl get blocknginxdangerousannotations -A 2>/dev/null || \
    echo "(Constraint 미적용 또는 violation 없음)"
  echo ""
  kubectl describe blocknginxdangerousannotations block-dangerous-nginx-annotations 2>/dev/null | \
    grep -A 20 "Violations:" || echo "(violation 상세 없음)"
}

cmd_uninstall() {
  echo "[Gatekeeper] 정책 제거..."
  kubectl delete -f "$CONSTRAINT_FILE" --ignore-not-found
  kubectl delete -f "$TEMPLATE_FILE" --ignore-not-found
  echo "[Gatekeeper] Helm 제거..."
  helm uninstall gatekeeper -n "$GK_NS" 2>/dev/null || true
  kubectl delete namespace "$GK_NS" --ignore-not-found
  echo "[Gatekeeper] 제거 완료"
}

case "${1:-install}" in
  install)    cmd_install ;;
  policy)     cmd_policy ;;
  violations) cmd_violations ;;
  uninstall)  cmd_uninstall ;;
  *)
    echo "사용법: $0 [install|policy|violations|uninstall]"
    exit 1
    ;;
esac
