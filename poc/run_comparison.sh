#!/usr/bin/env bash
# run_comparison.sh — CVE-2025-1974 비교 시연 실행 스크립트
#
# 사용법: bash poc/run_comparison.sh
#
# 수행 순서:
#   1) 클러스터 상태 확인
#   2) allow-snippet-annotations=true 로 패치 (취약 상태 재현)
#   3) port-forward 시작
#   4) 비교 A/B 실행
#   5) 종료 시 자동 복원 (allow=false, port-forward 종료)
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

WEBHOOK_PORT=8443
PF_PID_FILE="/tmp/poc_cmp_pf.pid"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

cleanup() {
    if [[ -f "$PF_PID_FILE" ]]; then
        kill "$(cat "$PF_PID_FILE")" 2>/dev/null || true
        rm -f "$PF_PID_FILE"
    fi
    kubectl patch cm ingress-nginx-controller -n ingress-nginx \
        --type=merge -p '{"data":{"allow-snippet-annotations":"false"}}' \
        --output=jsonpath='' 2>/dev/null || true
    echo ""
    echo "[정리] allow-snippet-annotations 복원 완료"
}
trap cleanup EXIT

# ── 사전 확인 ─────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo "  CVE-2025-1974 비교 시연"
echo "======================================================"

command -v kubectl >/dev/null || { echo "[오류] kubectl 없음. PATH 확인 필요"; exit 1; }
command -v python3 >/dev/null || { echo "[오류] python3 없음"; exit 1; }

echo "[1/4] 클러스터 상태 확인..."
kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller \
    -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q Running \
    || { echo "[오류] ingress-nginx Pod가 Running 아님. 'make cluster-up' 실행 필요"; exit 1; }
echo "      클러스터 정상"

# ── 취약 상태 활성화 ──────────────────────────────────────────────────────────
echo ""
echo "[2/4] allow-snippet-annotations=true 로 패치 (취약 상태 재현)..."
kubectl patch cm ingress-nginx-controller -n ingress-nginx \
    --type=merge -p '{"data":{"allow-snippet-annotations":"true"}}' \
    --output=jsonpath='      현재값: {.data.allow-snippet-annotations}'
echo ""
sleep 2

# ── port-forward ──────────────────────────────────────────────────────────────
echo ""
echo "[3/4] port-forward 시작 (localhost:${WEBHOOK_PORT} → webhook:443)..."
kubectl port-forward svc/ingress-nginx-controller-admission \
    "${WEBHOOK_PORT}:443" -n ingress-nginx >/dev/null 2>&1 &
echo $! > "$PF_PID_FILE"

for i in $(seq 1 10); do
    sleep 1
    ss -tlnp 2>/dev/null | grep -q ":${WEBHOOK_PORT}" && break
    [[ $i -eq 10 ]] && { echo "[오류] port-forward 실패"; exit 1; }
done
echo "      준비됨"

# ── 비교 실행 ─────────────────────────────────────────────────────────────────
echo ""
echo "[4/4] 비교 A / B 실행..."
echo ""
python3 "$SCRIPT_DIR/comparison.py"
