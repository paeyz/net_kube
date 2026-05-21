#!/usr/bin/env bash
# Blue Team 2: M5 full-stack integration validation with M2 + M3 + M4.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/blue2/common.sh
source "${SCRIPT_DIR}/common.sh"

ASSUME_YES=false

usage() {
    cat <<'EOF'
Usage: scripts/blue2/m5_fullstack_validation.sh [--yes]

Runs local Minikube-only M5 validation with M2 + M3 + M4 and writes sanitized
logs under results/blue2/<timestamp>-m5/.

  --yes     Proceed without an interactive confirmation.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes)
            ASSUME_YES=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[ERROR] unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

capture_can_i() {
    local namespace="$1"
    local logfile="$2"
    local out status answer

    set +e
    out="$(kubectl auth can-i list secrets -n "$namespace" --as="$INGRESS_NGINX_SA_REF" 2>&1)"
    status=$?
    set -e

    {
        echo "## RBAC can-i check"
        echo "\$ kubectl auth can-i list secrets -n ${namespace} --as=${INGRESS_NGINX_SA_REF}"
        echo
        printf '%s\n' "$out"
        echo
        echo "## exit_status: ${status}"
    } | redact_sensitive >"$logfile"

    answer="$(printf '%s\n' "$out" | awk 'tolower($0)=="yes" || tolower($0)=="no" {print tolower($0); exit}')"
    if [[ -z "$answer" ]]; then
        answer="error"
    fi
    printf '%s\n' "$answer"
}

check_networkpolicy_cni() {
    local logfile="$1"
    local cni_lines status

    cni_lines="$(kubectl get pods -A --no-headers 2>/dev/null \
        | awk '{print $1" "$2}' \
        | grep -Ei 'calico|cilium|antrea|weave|canal|kube-router' || true)"
    if [[ -n "$cni_lines" ]]; then
        status="candidate-found"
    else
        status="not-confirmed"
    fi

    {
        echo "networkpolicy_cni_status: ${status}"
        echo
        if [[ -n "$cni_lines" ]]; then
            echo "$cni_lines"
        else
            echo "No common NetworkPolicy-capable CNI pods were detected."
            echo "M2 NetworkPolicy may not be enforced in this environment."
        fi
    } | redact_sensitive >"$logfile"

    printf '%s\n' "$status"
}

docker_ready() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

log_status_from_file() {
    local logfile="$1"
    if grep -Eq '## exit_status: 0$' "$logfile" 2>/dev/null; then
        echo "Ran"
    elif [[ -f "$logfile" ]]; then
        echo "Ran with errors"
    else
        echo "Not run"
    fi
}

main() {
    require_cmd kubectl make

    local result_dir
    result_dir="$(make_result_dir "m5")"
    echo "[blue2] result directory: ${result_dir#${LAB_ROOT}/}"

    check_kube_context
    if ! kubectl get namespace "$INGRESS_NGINX_NAMESPACE" >/dev/null 2>&1; then
        echo "[ERROR] namespace not found: ${INGRESS_NGINX_NAMESPACE}" >&2
        exit 1
    fi

    {
        echo "# Kubernetes context"
        echo "current_context: $(kubectl config current-context 2>/dev/null || true)"
        echo "cluster_server: $(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)"
        echo
        echo "# controller image"
        current_ingress_nginx_image
    } | redact_sensitive >"${result_dir}/context.txt"

    local cni_status
    cni_status="$(check_networkpolicy_cni "${result_dir}/networkpolicy_cni_check.txt")"
    if [[ "$cni_status" != "candidate-found" ]]; then
        echo "[WARN] NetworkPolicy-capable CNI was not confirmed; M2 may not be enforceable."
    fi

    confirm_or_exit "This will apply M2, M3, M4, run port-forward attack validation, and optionally run the in-cluster attacker pod if Docker is available." "$ASSUME_YES"

    echo "[blue2] applying full stack defenses: M2 + M3 + M4"
    run_and_log "Apply M2 NetworkPolicy" "${result_dir}/apply_m2.log" \
        make -C "$LAB_ROOT" defense-m2 || true
    run_and_log "Apply M3 ValidatingAdmissionPolicy" "${result_dir}/apply_m3.log" \
        make -C "$LAB_ROOT" defense-m3 || true
    run_and_log "Apply M4 RBAC" "${result_dir}/apply_m4.log" \
        make -C "$LAB_ROOT" defense-m4 || true

    run_and_log "Record NetworkPolicies" "${result_dir}/networkpolicy_all.log" \
        kubectl get networkpolicy -A || true
    run_and_log "Record ValidatingAdmissionPolicies" "${result_dir}/validatingadmissionpolicy.log" \
        kubectl get validatingadmissionpolicy || true
    run_and_log "Record ingress-nginx Roles and RoleBindings" "${result_dir}/ingress_nginx_roles_rolebindings.log" \
        kubectl get role,rolebinding -n "$INGRESS_NGINX_NAMESPACE" || true

    local m4_can_i
    m4_can_i="$(capture_can_i kube-system "${result_dir}/m4_can_i_kube_system.log")"

    echo "[blue2] running port-forward based attack-chain validation"
    local port_forward_pf_log
    port_forward_pf_log="${result_dir}/m5_portforward.log"
    run_and_log "M5 port-forward attack-chain" "${result_dir}/port_forward_attack_chain.log" \
        make -C "$LAB_ROOT" "ATTACK_OUT=${result_dir}/m5-port-forward-attack-results" "PF_LOG_FILE=${port_forward_pf_log}" attack-chain || true
    sanitize_file_in_place "$port_forward_pf_log"

    local docker_validation docker_skip_reason
    docker_validation="not-run"
    docker_skip_reason=""
    if docker_ready; then
        docker_validation="ran"
        echo "[blue2] Docker is available; running in-cluster attacker pod validation"
        run_and_log "Docker build attacker image" "${result_dir}/docker_build.log" \
            make -C "$LAB_ROOT" docker-build || true
        run_and_log "Deploy attacker pod" "${result_dir}/attacker_deploy.log" \
            make -C "$LAB_ROOT" attacker-deploy || true
        run_and_log "Wait attacker pod" "${result_dir}/attacker_wait.log" \
            kubectl wait --for=condition=Ready pod/attacker-pod -n default --timeout=60s || true
        run_and_log "Attacker pod logs" "${result_dir}/attacker_logs.log" \
            make -C "$LAB_ROOT" attacker-logs || true
        run_and_log "Delete attacker pod" "${result_dir}/attacker_delete.log" \
            make -C "$LAB_ROOT" attacker-delete || true
    else
        docker_skip_reason="Docker command or daemon is not available; M2 cannot be fully proven without in-cluster attacker pod testing."
        printf '%s\n' "$docker_skip_reason" >"${result_dir}/attacker_pod_validation_skipped.txt"
        echo "[blue2] ${docker_skip_reason}"
    fi

    local m2_result m3_result m4_result port_forward_result attacker_result
    m2_result="$(log_status_from_file "${result_dir}/apply_m2.log")"
    if [[ "$cni_status" != "candidate-found" ]]; then
        m2_result="${m2_result}; enforcement not confirmed"
    fi
    if grep -q 'block-dangerous-nginx-annotations' "${result_dir}/validatingadmissionpolicy.log" 2>/dev/null; then
        m3_result="Policy present"
    else
        m3_result="$(log_status_from_file "${result_dir}/apply_m3.log")"
    fi
    if [[ "$m4_can_i" == "no" ]]; then
        m4_result="kube-system Secrets list denied"
    else
        m4_result="kube-system Secrets list=${m4_can_i}"
    fi
    port_forward_result="$(summarize_status "${result_dir}/port_forward_attack_chain.log")"
    if [[ "$docker_validation" == "ran" ]]; then
        attacker_result="$(summarize_status "${result_dir}/attacker_logs.log")"
    else
        attacker_result="Skipped: ${docker_skip_reason}"
    fi

    cat >"${result_dir}/summary.md" <<EOF
# Blue Team 2 M5 Full Stack 통합 검증 요약

- 결과 디렉터리: \`${result_dir#${LAB_ROOT}/}\`
- Kubernetes context: \`$(kubectl config current-context 2>/dev/null || echo unknown)\`
- 적용 조합: M2 NetworkPolicy + M3 ValidatingAdmissionPolicy + M4 RBAC
- NetworkPolicy CNI 확인: \`${cni_status}\`

## 핵심 결과

| 항목 | 결과 |
|---|---|
| M2 NetworkPolicy 적용/집행 | \`${m2_result}\` |
| M3 ValidatingAdmissionPolicy | \`${m3_result}\` |
| M4 RBAC kube-system Secrets 제한 | \`${m4_result}\` |
| Docker attacker pod 검증 실행 | \`${docker_validation}\` |
| attacker pod 검증 결과 | \`${attacker_result}\` |
| port-forward attack-chain 결과 | \`${port_forward_result}\` |

## 해석

- M2는 클러스터 내부 공격자 파드가 webhook에 직접 접근하는 경로를 제한하는 방어다. NetworkPolicy-capable CNI가 없으면 정책 객체는 존재해도 실제 차단이 보장되지 않는다.
- M3는 kube-apiserver 경유 Ingress 생성/수정에서 위험한 \`auth-snippet\` 또는 \`server-snippet\`을 차단한다.
- M4는 토큰 탈취 이후 Kubernetes API lateral movement의 blast radius를 줄인다.
- port-forward 기반 경로는 kube-apiserver를 경유하므로 M2의 직접 네트워크 차단 검증과 성격이 다르다. 따라서 M2 완전 검증에는 in-cluster attacker pod 로그가 가장 중요하다.
- M2가 초기에 차단하면 D3 토큰 파일 접근과 D4 탈취 토큰 API 접근이 발생하지 않을 수 있으며, 이는 기대 가능한 방어 결과다.

## Detection Team 매핑

| 탐지 | 연결되는 공격/방어 지점 |
|---|---|
| D1 | admission webhook 직접 접근 시도. M2 attacker pod 검증과 연결 |
| D2 | 위험한 nginx annotation 생성 시도. M3 VAP/Gatekeeper/Audit와 연결 |
| D3 | controller Pod 내부 ServiceAccount token 파일 접근. B1/M2가 초기에 막으면 미발생 가능 |
| D4 | 탈취 토큰으로 Kubernetes API 접근. M4 이후 Forbidden 결과가 기대됨 |

## 관련 로그

| 로그 | 설명 |
|---|---|
| \`networkpolicy_cni_check.txt\` | NetworkPolicy 집행 가능 CNI 후보 확인 |
| \`apply_m2.log\` | M2 적용 |
| \`apply_m3.log\` | M3 적용 |
| \`apply_m4.log\` | M4 적용 |
| \`m4_can_i_kube_system.log\` | M4 kube-system Secrets 권한 확인 |
| \`port_forward_attack_chain.log\` | port-forward 기반 공격 체인 |
| \`m5_portforward.log\` | M5 port-forward 로그 |
| \`attacker_logs.log\` | Docker 사용 가능 시 in-cluster attacker pod 결과 |
EOF

    echo "[blue2] summary written: ${result_dir#${LAB_ROOT}/}/summary.md"
}

main "$@"
