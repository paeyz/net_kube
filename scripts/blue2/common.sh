#!/usr/bin/env bash
# Shared helpers for Blue Team 2 validation scripts.
set -euo pipefail

BLUE2_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "${BLUE2_COMMON_DIR}/../.." && pwd)"
BLUE2_RESULTS_ROOT="${BLUE2_RESULTS_ROOT:-${LAB_ROOT}/results/blue2}"

INGRESS_NGINX_NAMESPACE="${INGRESS_NGINX_NAMESPACE:-ingress-nginx}"
INGRESS_NGINX_SERVICEACCOUNT="${INGRESS_NGINX_SERVICEACCOUNT:-ingress-nginx}"
INGRESS_NGINX_SA_REF="system:serviceaccount:${INGRESS_NGINX_NAMESPACE}:${INGRESS_NGINX_SERVICEACCOUNT}"
INGRESS_NGINX_TOKEN_PATH="/var/run/secrets/kubernetes.io/serviceaccount/token"
M4_MINIMAL_CLUSTERROLEBINDING="${M4_MINIMAL_CLUSTERROLEBINDING:-ingress-nginx-webhook-read}"

require_cmd() {
    local missing=0
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "[ERROR] required command not found: ${cmd}" >&2
            missing=1
        fi
    done
    if [[ "$missing" -ne 0 ]]; then
        exit 127
    fi
}

timestamp() {
    date +"%Y%m%dT%H%M%S%z"
}

make_result_dir() {
    local suffix="$1"
    local ts
    ts="$(timestamp)"
    local dir="${BLUE2_RESULTS_ROOT}/${ts}-${suffix}"
    mkdir -p "$dir"
    printf '%s\n' "$dir"
}

redact_sensitive() {
    if command -v perl >/dev/null 2>&1; then
        perl -pe '
            s/(Authorization[[:space:]]*:[[:space:]]*)(Bearer[[:space:]]+)?[^[:space:]\r\n]+/${1}<REDACTED>/ig;
            s/(authorization[[:space:]]*=[[:space:]]*)(Bearer[[:space:]]+)?[^[:space:]\r\n]+/${1}<REDACTED>/ig;
            s/(Bearer[[:space:]]+)[A-Za-z0-9._~+\/=-]{16,}/${1}<REDACTED>/g;
            s/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/<REDACTED_JWT>/g;
            s/eyJ[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{8,})?(?:\.\.\.)?/<REDACTED_JWT_PREVIEW>/g;
            s/(토큰[^:：]*[:：][[:space:]]*)[^[:space:]]+/${1}<REDACTED>/g;
            s/(\b(?:token|id-token|access-token|refresh-token|password|passwd|secret|client-key-data|client-certificate-data|certificate-authority-data)\b[[:space:]]*[:=][[:space:]]*)("[^"]*"|'\''[^'\'']*'\''|[^[:space:],}]+)/${1}<REDACTED>/ig;
            s/^([[:space:]]*[A-Za-z0-9_.-]*(?:token|secret|password|ca\.crt|tls\.crt|tls\.key)[A-Za-z0-9_.-]*[[:space:]]*:[[:space:]]*)[A-Za-z0-9+\/_-]{16,}={0,2}[[:space:]]*$/${1}<REDACTED>/i;
            s/[A-Za-z0-9+\/_-]{80,}={0,2}/<REDACTED_BASE64>/g;
        '
    else
        sed -E \
            -e 's/(Authorization[[:space:]]*:[[:space:]]*)(Bearer[[:space:]]+)?[^[:space:]]+/\1<REDACTED>/Ig' \
            -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._~+\/=-]{16,}/\1<REDACTED>/g' \
            -e 's/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/<REDACTED_JWT>/g' \
            -e 's/eyJ[A-Za-z0-9_-]{20,}(\.[A-Za-z0-9_-]{8,})?(\.\.\.)?/<REDACTED_JWT_PREVIEW>/g' \
            -e 's/[A-Za-z0-9+\/_-]{80,}={0,2}/<REDACTED_BASE64>/g'
    fi
}

_quote_command() {
    printf '%q ' "$@"
}

run_and_log() {
    local label="$1"
    local logfile="$2"
    shift 2

    mkdir -p "$(dirname "$logfile")"
    local tmp
    tmp="$(mktemp)"

    set +e
    {
        echo "## ${label}"
        echo "## started: $(date -Iseconds)"
        echo "\$ $(_quote_command "$@")"
        echo
        "$@"
    } >"$tmp" 2>&1
    local status=$?
    set -e

    {
        cat "$tmp"
        echo
        echo "## exit_status: ${status}"
        echo "## finished: $(date -Iseconds)"
    } | redact_sensitive >"$logfile"
    rm -f "$tmp"

    echo "[blue2] ${label}: exit ${status} -> ${logfile#${LAB_ROOT}/}"
    return "$status"
}

sanitize_file_in_place() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    local tmp
    tmp="$(mktemp)"
    redact_sensitive <"$file" >"$tmp"
    mv "$tmp" "$file"
}

confirm_or_exit() {
    local message="$1"
    local assume_yes="${2:-false}"

    if [[ "$assume_yes" == "true" || "$assume_yes" == "1" ]]; then
        echo "[blue2] --yes supplied. Proceeding: ${message}"
        return 0
    fi

    echo "[blue2] ${message}"
    if [[ ! -t 0 ]]; then
        echo "[ERROR] Non-interactive shell. Re-run with --yes after reviewing the action." >&2
        exit 1
    fi

    local answer
    read -r -p "Type 'yes' to continue: " answer
    if [[ "$answer" != "yes" ]]; then
        echo "[blue2] cancelled"
        exit 1
    fi
}

check_kube_context() {
    local ctx
    local server

    ctx="$(kubectl config current-context 2>/dev/null || true)"
    server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)"

    if [[ -z "$ctx" ]]; then
        echo "[ERROR] kubectl current-context is empty." >&2
        exit 1
    fi

    echo "[blue2] current kubectl context: ${ctx}"
    echo "[blue2] current cluster server: ${server:-unknown}"

    if [[ "$ctx" == *minikube* || "$ctx" == *cve-2025-1974* ]]; then
        return 0
    fi

    if [[ "$server" =~ ^https://(127\.0\.0\.1|localhost|\[::1\])(:|/) ]]; then
        return 0
    fi

    echo "[ERROR] Refusing to run outside a local Minikube-style context." >&2
    echo "[ERROR] Expected context name containing 'minikube' or 'cve-2025-1974', or a localhost API server." >&2
    exit 1
}

current_ingress_nginx_image() {
    kubectl get deploy ingress-nginx-controller -n "$INGRESS_NGINX_NAMESPACE" \
        -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{"="}{.image}{"\n"}{end}' 2>/dev/null \
        || kubectl get pods -n "$INGRESS_NGINX_NAMESPACE" \
            -l app.kubernetes.io/component=controller \
            -o jsonpath='{range .items[0].spec.containers[*]}{.name}{"="}{.image}{"\n"}{end}' 2>/dev/null \
        || true
}

current_helm_release() {
    helm list -n "$INGRESS_NGINX_NAMESPACE" --filter '^ingress-nginx$' 2>&1 || true
}

get_ingress_controller_pod() {
    kubectl get pods -n "$INGRESS_NGINX_NAMESPACE" \
        -l app.kubernetes.io/component=controller \
        --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

write_section() {
    local file="$1"
    local title="$2"
    {
        echo
        echo "## ${title}"
        cat
    } >>"$file"
}

summarize_status() {
    local logfile="$1"
    if [[ ! -f "$logfile" ]]; then
        echo "not-run"
        return 0
    fi
    if grep -Eqi 'Forbidden|forbidden|denied|Deny|차단|blocked|not allowed' "$logfile"; then
        echo "blocked-or-forbidden"
    elif grep -Eqi '토큰 추출 성공|우회 성공|Lateral Move.*성공|\[OK\].*T[23]|allowed[[:space:]]*:[[:space:]]*True' "$logfile"; then
        echo "reached"
    elif grep -Eqi 'FAIL|failed|실패|error|오류' "$logfile"; then
        echo "failed-or-unknown"
    else
        echo "unknown"
    fi
}

safe_kubectl_token_test() {
    local token="$1"
    local namespace="$2"
    local logfile="$3"

    mkdir -p "$(dirname "$logfile")"
    if [[ -z "$token" ]]; then
        {
            echo "## kubectl token authorization test"
            echo "token unavailable; test skipped"
            echo "## exit_status: 99"
        } >"$logfile"
        return 99
    fi

    local server
    server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)"
    if [[ -z "$server" ]]; then
        {
            echo "## isolated token authorization test"
            echo "cluster server unavailable; test skipped"
            echo "## exit_status: 98"
        } >"$logfile"
        return 98
    fi

    local tmp tmp_kubeconfig
    tmp="$(mktemp)"
    tmp_kubeconfig="$(mktemp)"
    chmod 600 "$tmp_kubeconfig"

    local kubectl_status=0
    set +e
    {
        echo "## isolated token authorization test"
        echo "## started: $(date -Iseconds)"
        echo "\$ KUBECONFIG=<isolated-empty> kubectl --server=<local-cluster> --insecure-skip-tls-verify=true --token=<REDACTED> auth can-i list secrets -n ${namespace}"
        echo
        local decision
        decision="$(
            KUBECONFIG="$tmp_kubeconfig" kubectl \
                --server="$server" \
                --insecure-skip-tls-verify=true \
                --token="$token" \
                auth can-i list secrets -n "$namespace" 2>&1
        )"
        kubectl_status=$?
        printf 'authorization_decision: %s\n' "$decision"
        echo "kubectl_exit_status: ${kubectl_status}"
    } >"$tmp" 2>&1
    local status=$kubectl_status
    set -e

    {
        cat "$tmp"
        echo
        echo "## exit_status: ${status}"
        echo "## finished: $(date -Iseconds)"
    } | redact_sensitive >"$logfile"
    rm -f "$tmp" "$tmp_kubeconfig"

    echo "[blue2] isolated token test namespace=${namespace}: exit ${status} -> ${logfile#${LAB_ROOT}/}"
    return "$status"
}
