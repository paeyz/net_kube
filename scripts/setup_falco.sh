#!/usr/bin/env bash
# Detection Team — Falco 설치 + CVE-2025-1974 커스텀 룰 적용
#
# 사용법: bash scripts/setup_falco.sh [install|rules|status|logs|uninstall]
#
# 전제: make cluster-up 실행 완료, helm CLI 사용 가능
# 참고: https://falco.org/docs/install-operate/installation/

set -euo pipefail

FALCO_NS="falco"
RULES_FILE="$(dirname "$0")/../monitoring/falco-rules.yaml"
RULES_CM_NAME="falco-cve-2025-1974-rules"
HELM_RULES_KEY="customRules.falco_rules\\.local\\.yaml"

_check_helm() {
  if ! command -v helm &>/dev/null; then
    echo "[ERROR] helm이 필요합니다: https://helm.sh/docs/intro/install/"
    exit 1
  fi
}

cmd_install() {
  _check_helm
  echo "[Falco] Helm repo 추가..."
  helm repo add falcosecurity https://falcosecurity.github.io/charts
  helm repo update

  echo "[Falco] Falco 설치 (falco namespace)..."
  kubectl create namespace "$FALCO_NS" --dry-run=client -o yaml | kubectl apply -f -

  # Minikube driver=docker 환경에서는 ebpf 대신 modern_ebpf 또는 syscall 사용
  helm upgrade --install falco falcosecurity/falco \
    --namespace "$FALCO_NS" \
    --set driver.kind=modern_ebpf \
    --set falcosidekick.enabled=true \
    --set falcosidekick.webui.enabled=true \
    --set "falco.json_output=true" \
    --set "falco.log_level=info" \
    --set-file "$HELM_RULES_KEY=$RULES_FILE" \
    --wait --timeout 5m

  echo "[Falco] 설치 완료"
  kubectl get pods -n "$FALCO_NS"

  # 커스텀 룰 적용
  cmd_rules
}

cmd_rules() {
  _check_helm
  echo "[Falco] CVE-2025-1974 커스텀 룰 적용..."
  if [ ! -f "$RULES_FILE" ]; then
    echo "[ERROR] $RULES_FILE 이 없습니다"
    exit 1
  fi

  kubectl create configmap "$RULES_CM_NAME" \
    --from-file=falco_rules.local.yaml="$RULES_FILE" \
    -n "$FALCO_NS" \
    --dry-run=client -o yaml | kubectl apply -f -

  if ! helm status falco -n "$FALCO_NS" >/dev/null 2>&1; then
    echo "[Falco] Falco Helm release가 없어 설치를 먼저 진행합니다..."
    cmd_install
    return
  fi

  # Falco chart의 customRules는 falco-rules ConfigMap을 만들고
  # /etc/falco/rules.d 로 마운트한다. 단순 ConfigMap 생성만으로는 Falco가 읽지 않는다.
  echo "[Falco] Helm customRules로 Falco DaemonSet에 룰 마운트..."
  helm upgrade falco falcosecurity/falco \
    --namespace "$FALCO_NS" \
    --reuse-values \
    --set-file "$HELM_RULES_KEY=$RULES_FILE" \
    --wait --timeout 5m

  kubectl rollout status daemonset/falco -n "$FALCO_NS" --timeout=120s 2>/dev/null || true

  echo "[Falco] 룰 적용 완료"
  echo "  확인: make detect-falco-logs"
}

cmd_status() {
  echo "=== Falco 상태 ==="
  kubectl get pods -n "$FALCO_NS" -o wide 2>/dev/null || echo "(falco 네임스페이스 없음)"
  echo ""
  echo "=== 커스텀 룰 ConfigMap ==="
  kubectl get configmap "$RULES_CM_NAME" -n "$FALCO_NS" 2>/dev/null || echo "(룰 미적용)"
  echo ""
  echo "=== Helm customRules ConfigMap ==="
  kubectl get configmap falco-rules -n "$FALCO_NS" 2>/dev/null || echo "(Helm customRules 미적용)"
}

cmd_logs() {
  echo "[Falco] 최근 알림 (Ctrl+C로 종료)..."
  POD=$(kubectl get pods -n "$FALCO_NS" -l app.kubernetes.io/name=falco \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  if [ -z "$POD" ]; then
    echo "[ERROR] Falco 파드를 찾을 수 없습니다"
    exit 1
  fi
  kubectl logs -f "$POD" -n "$FALCO_NS" --tail=50
}

cmd_uninstall() {
  echo "[Falco] 제거..."
  helm uninstall falco -n "$FALCO_NS" 2>/dev/null || true
  kubectl delete namespace "$FALCO_NS" --ignore-not-found
  echo "[Falco] 제거 완료"
}

case "${1:-install}" in
  install)   cmd_install ;;
  rules)     cmd_rules ;;
  status)    cmd_status ;;
  logs)      cmd_logs ;;
  uninstall) cmd_uninstall ;;
  *)
    echo "사용법: $0 [install|rules|status|logs|uninstall]"
    exit 1
    ;;
esac
