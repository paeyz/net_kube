#!/usr/bin/env bash
# M1 — Webhook Disabled Mitigation
#
# admission webhook을 비활성화하여 direct POST 공격 경로를 차단한다.
# 단점: ingress-nginx 자체 validation이 꺼지므로 운영 환경에서는 비적합.
# 학습 목적: M1 적용 후 make attack-chain → webhook 도달 불가 확인.
#
# 사용법:
#   bash defense/m1-webhook-disable.sh apply    # webhook 비활성화
#   bash defense/m1-webhook-disable.sh restore  # webhook 복원

set -euo pipefail

ACTION="${1:-apply}"
WEBHOOK_NAME="ingress-nginx-admission"

case "$ACTION" in
  apply)
    echo "[M1] admission webhook 비활성화..."
    kubectl delete validatingwebhookconfiguration "$WEBHOOK_NAME" --ignore-not-found
    echo "[M1] 완료 — direct POST 공격 경로 차단됨"
    echo "     검증: make attack-chain → webhook 연결 실패 확인"
    ;;
  restore)
    echo "[M1] webhook 복원 — ingress-nginx helm upgrade로 재생성..."
    # helm upgrade는 webhook을 자동 재생성
    helm upgrade ingress-nginx ingress-nginx/ingress-nginx \
      -n ingress-nginx \
      --reuse-values \
      --wait
    echo "[M1] 복원 완료"
    kubectl get validatingwebhookconfiguration "$WEBHOOK_NAME"
    ;;
  *)
    echo "사용법: $0 [apply|restore]"
    exit 1
    ;;
esac
