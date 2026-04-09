#!/usr/bin/env bash
# run_comparison.sh — CVE-2025-1974 비교 시연 실행 스크립트
#
# 사용법: bash poc/run_comparison.sh
#
# 수행 순서:
#   1) 클러스터 상태 + allow-snippet-annotations 현재값 확인
#   2) port-forward 시작
#   3) 비교 A/B 실행
#   4) 종료 시 port-forward 자동 정리
#
# ★ ConfigMap 패치 없음 — allow-snippet-annotations 기본값(false) 그대로 사용
#   A: configuration-snippet → 차단됨 (정상)
#   B: auth-snippet          → 차단 우회 (CVE-2025-1974 핵심)
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
    echo ""
    echo "[정리] port-forward 종료"
}
trap cleanup EXIT

# ── 사전 확인 ─────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo "  CVE-2025-1974 비교 시연 (allow-snippet-annotations=false)"
echo "======================================================"

command -v kubectl >/dev/null || { echo "[오류] kubectl 없음. PATH 확인 필요"; exit 1; }
command -v python3 >/dev/null || { echo "[오류] python3 없음"; exit 1; }

echo "[1/3] 클러스터 상태 확인..."
kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller \
    -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q Running \
    || { echo "[오류] ingress-nginx Pod가 Running 아님. 'make cluster-up' 실행 필요"; exit 1; }
echo "      클러스터 정상"

# 현재 allow-snippet-annotations 값 출력 (패치하지 않음)
SNIPPET_VAL=$(kubectl get cm ingress-nginx-controller -n ingress-nginx \
    -o jsonpath='{.data.allow-snippet-annotations}' 2>/dev/null || echo "false")
echo "      allow-snippet-annotations = ${SNIPPET_VAL:-false}"
echo "      (패치 없이 현재 값 그대로 사용 — 기본값은 false)"

# ── port-forward ──────────────────────────────────────────────────────────────
echo ""
echo "[2/3] port-forward 시작 (localhost:${WEBHOOK_PORT} → webhook:443)..."
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
echo "[3/3] 비교 A / B 실행..."
echo ""
python3 "$SCRIPT_DIR/comparison.py"
