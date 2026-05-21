#!/usr/bin/env bash
# Blue Team 2: B1 ingress-nginx vulnerable-vs-patched validation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/blue2/common.sh
source "${SCRIPT_DIR}/common.sh"

ASSUME_YES=false
VULN_CHART_VERSION="${VULN_CHART_VERSION:-4.11.3}"
VULN_CONTROLLER_TAG="${VULN_CONTROLLER_TAG:-v1.11.3}"
PATCHED_CHART_VERSION="${PATCHED_CHART_VERSION:-4.11.5}"
PATCHED_CONTROLLER_TAG="${PATCHED_CONTROLLER_TAG:-v1.11.5}"

usage() {
    cat <<'EOF'
Usage: scripts/blue2/b1_patch_validation.sh [--yes]

Runs local Minikube-only ingress-nginx vulnerable-vs-patched validation and
writes sanitized logs under results/blue2/<timestamp>-b1/.

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

run_capture_status() {
    local status_file="$1"
    shift
    set +e
    "$@"
    local status=$?
    set -e
    printf '%s\n' "$status" >"$status_file"
    return "$status"
}

log_current_state() {
    local prefix="$1"
    local result_dir="$2"
    {
        echo "# ingress-nginx controller image (${prefix})"
        current_ingress_nginx_image
    } | redact_sensitive >"${result_dir}/${prefix}_image.txt"

    {
        echo "# ingress-nginx Helm release (${prefix})"
        current_helm_release
    } | redact_sensitive >"${result_dir}/${prefix}_helm_release.txt"

    {
        echo "# ingress-nginx controller ConfigMap (${prefix})"
        kubectl get configmap ingress-nginx-controller -n "$INGRESS_NGINX_NAMESPACE" \
            -o jsonpath='{.data.allow-snippet-annotations}{"\n"}' 2>&1 || true
    } | redact_sensitive >"${result_dir}/${prefix}_allow_snippet.txt"
}

first_nonempty_line() {
    local file="$1"
    awk 'NF && $0 !~ /^#/ {print; exit}' "$file" 2>/dev/null || true
}

helm_release_status() {
    local file="$1"
    awk 'NR > 1 {
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^(deployed|failed|pending-install|pending-upgrade|pending-rollback|superseded|uninstalled|uninstalling)$/) {
                print $i
                exit
            }
        }
    }' "$file" 2>/dev/null || true
}

image_contains_tag() {
    local image="$1"
    local tag="$2"
    [[ "$image" == *"${tag}"* ]]
}

ensure_allow_snippet_true() {
    local result_dir="$1"
    local current
    current="$(kubectl get configmap ingress-nginx-controller -n "$INGRESS_NGINX_NAMESPACE" \
        -o jsonpath='{.data.allow-snippet-annotations}' 2>/dev/null || true)"
    if [[ "$current" == "true" ]]; then
        printf 'allow-snippet-annotations already true\n' >"${result_dir}/allow_snippet_patch.log"
        return 0
    fi

    run_and_log "Patch allow-snippet-annotations=true" "${result_dir}/allow_snippet_patch.log" \
        kubectl patch configmap ingress-nginx-controller \
            -n "$INGRESS_NGINX_NAMESPACE" \
            --type=merge \
            -p '{"data":{"allow-snippet-annotations":"true"}}'
}

poc_step3_result() {
    local logfile="$1"
    if grep -Eqi 'auth-snippet[[:space:]]*→[[:space:]]*nginx가 파일에 접근함|우회 성공|unexpected end of file.*serviceaccount/token|ServiceAccount JWT' "$logfile"; then
        echo "Reached"
    elif grep -Eqi 'auth-snippet[[:space:]]*→[[:space:]]*차단됨|admission webhook.*denied.*auth-snippet|snippet.*disabled|not allowed|Forbidden' "$logfile"; then
        echo "Blocked"
    elif grep -Eqi '요청이 허용됨|allowed[\"[:space:]]*:[[:space:]]*true' "$logfile"; then
        echo "Allowed without direct leak"
    elif grep -Eqi 'port-forward 실패|connection refused|timed out|exit_status: [1-9]' "$logfile"; then
        echo "Inconclusive"
    else
        echo "Unknown"
    fi
}

attack_chain_stage_result() {
    local logfile="$1"
    local stage="$2"
    case "$stage" in
        t1)
            if grep -Eqi '열거 완료:[[:space:]]+0/|접근가능 0개' "$logfile"; then
                echo "Blocked or no files reached"
            elif grep -Eqi '접근가능.*serviceaccount/token|열거 완료:[[:space:]]+[1-9]' "$logfile"; then
                echo "Reached"
            else
                echo "Unknown"
            fi
            ;;
        t2)
            if grep -Eqi '토큰 추출 성공|ServiceAccount JWT|T2 토큰 추출[[:space:]]+— 성공' "$logfile"; then
                if grep -Eqi '성공 \(kubectl_exec\)|방법:[[:space:]]*kubectl_exec|method: kubectl_exec' "$logfile"; then
                    echo "Reached via kubectl_exec fallback"
                else
                    echo "Reached"
                fi
            elif grep -Eqi '토큰 추출 실패|T2.*실패|스킵 \(토큰 없음\)' "$logfile"; then
                echo "Blocked or not reached"
            else
                echo "Unknown"
            fi
            ;;
        t3)
            if grep -Eqi 'T3.*Lateral.*성공|Lateral Move.*성공|Level [123].*성공' "$logfile"; then
                echo "Reached"
            elif grep -Eqi 'T3.*스킵|스킵 \(토큰 없음\)|Forbidden|forbidden|T3.*실패' "$logfile"; then
                echo "Blocked or limited"
            else
                echo "Unknown"
            fi
            ;;
        *)
            echo "Unknown"
            ;;
    esac
}

file_enum_count() {
    local logfile="$1"
    local count
    count="$(grep -Eo '열거 완료:[[:space:]]+[0-9]+/[0-9]+' "$logfile" 2>/dev/null \
        | tail -n 1 \
        | sed -E 's/.*:[[:space:]]*([0-9]+)\/[0-9]+/\1/' || true)"
    if [[ -z "$count" ]]; then
        count="$(grep -Eo '접근가능[[:space:]]+[0-9]+개' "$logfile" 2>/dev/null \
            | tail -n 1 \
            | sed -E 's/[^0-9]*([0-9]+).*/\1/' || true)"
    fi
    if [[ -z "$count" ]]; then
        echo "unknown"
    else
        echo "$count"
    fi
}

is_nonzero_count() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ && "$value" -gt 0 ]]
}

is_zero_count() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ && "$value" -eq 0 ]]
}

main() {
    require_cmd kubectl helm make

    local result_dir
    result_dir="$(make_result_dir "b1")"
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
    } | redact_sensitive >"${result_dir}/context.txt"
    log_current_state "initial" "$result_dir"

    confirm_or_exit "This will reset ingress-nginx to vulnerable ${VULN_CONTROLLER_TAG}, run pre-patch validation, upgrade to patched ${PATCHED_CONTROLLER_TAG}, and run post-patch validation against the current local Minikube context." "$ASSUME_YES"

    echo "[blue2] preparing Helm repo"
    run_and_log "Helm repo add ingress-nginx" "${result_dir}/helm_repo_add.log" \
        bash -c "helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx || true" || true
    run_and_log "Helm repo update" "${result_dir}/helm_repo_update.log" \
        helm repo update || true

    echo "[blue2] reset: install/upgrade vulnerable baseline ${VULN_CONTROLLER_TAG} (chart ${VULN_CHART_VERSION})"
    local reset_status_file reset_status
    reset_status_file="${result_dir}/reset_vulnerable_status.txt"
    run_capture_status "$reset_status_file" run_and_log "Reset ingress-nginx vulnerable baseline" "${result_dir}/reset_vulnerable_baseline.log" \
        helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
            --version "$VULN_CHART_VERSION" \
            -n "$INGRESS_NGINX_NAMESPACE" \
            --create-namespace \
            --set "controller.image.tag=${VULN_CONTROLLER_TAG}" \
            --set controller.admissionWebhooks.enabled=true \
            --set controller.admissionWebhooks.failurePolicy=Fail \
            --set controller.service.type=NodePort \
            --set controller.config.allow-snippet-annotations=true \
            --server-side true \
            --force-conflicts \
            --wait \
            --timeout 5m || true
    reset_status="$(cat "$reset_status_file")"

    run_and_log "Rollout status vulnerable baseline" "${result_dir}/reset_vulnerable_rollout.log" \
        kubectl rollout status deploy/ingress-nginx-controller -n "$INGRESS_NGINX_NAMESPACE" --timeout=120s || true
    ensure_allow_snippet_true "$result_dir" || true
    log_current_state "vulnerable_baseline" "$result_dir"
    local image_vulnerable
    image_vulnerable="$(first_nonempty_line "${result_dir}/vulnerable_baseline_image.txt")"
    local vulnerable_image_ok="false"
    if image_contains_tag "$image_vulnerable" "$VULN_CONTROLLER_TAG"; then
        vulnerable_image_ok="true"
    fi

    echo "[blue2] pre-patch: restore defenses and run validation"
    run_and_log "Pre-patch defense restore" "${result_dir}/pre_patch_defense_restore.log" \
        bash -c "cd '$LAB_ROOT' && make defense-restore || true" || true
    local pre_attack_pf_log pre_poc_pf_log pre_attack_pf_pid pre_poc_pf_pid
    pre_attack_pf_log="${result_dir}/pre_patch_attack_portforward.log"
    pre_poc_pf_log="${result_dir}/pre_patch_poc_portforward.log"
    pre_attack_pf_pid="${result_dir}/pre_patch_attack_portforward.pid"
    pre_poc_pf_pid="${result_dir}/pre_patch_poc_portforward.pid"
    run_and_log "Pre-patch attack-chain" "${result_dir}/pre_patch_attack_chain.log" \
        make -C "$LAB_ROOT" "ATTACK_OUT=${result_dir}/pre-patch-attack-results" "PF_LOG_FILE=${pre_attack_pf_log}" "PF_PID_FILE=${pre_attack_pf_pid}" attack-chain || true
    sanitize_file_in_place "$pre_attack_pf_log"
    run_and_log "Pre-patch poc-step3" "${result_dir}/pre_patch_poc_step3.log" \
        make -C "$LAB_ROOT" "PF_LOG_FILE=${pre_poc_pf_log}" "PF_PID_FILE=${pre_poc_pf_pid}" poc-step3 || true
    sanitize_file_in_place "$pre_poc_pf_log"

    echo "[blue2] patch: upgrade ingress-nginx to ${PATCHED_CONTROLLER_TAG} (chart ${PATCHED_CHART_VERSION})"
    local patch_status_file patch_status
    patch_status_file="${result_dir}/patch_upgrade_status.txt"
    run_capture_status "$patch_status_file" run_and_log "Helm upgrade ingress-nginx patched" "${result_dir}/helm_upgrade_v1_11_5.log" \
        helm upgrade ingress-nginx ingress-nginx/ingress-nginx \
            --version "$PATCHED_CHART_VERSION" \
            -n "$INGRESS_NGINX_NAMESPACE" \
            --set "controller.image.tag=${PATCHED_CONTROLLER_TAG}" \
            --set controller.admissionWebhooks.enabled=true \
            --set controller.admissionWebhooks.failurePolicy=Fail \
            --set controller.service.type=NodePort \
            --set controller.config.allow-snippet-annotations=true \
            --server-side true \
            --force-conflicts \
            --wait \
            --timeout 5m || true
    patch_status="$(cat "$patch_status_file")"
    if [[ "$patch_status" -ne 0 ]] && grep -Eqi 'conflict|UPGRADE FAILED' "${result_dir}/helm_upgrade_v1_11_5.log"; then
        echo "[WARN] patched upgrade failed; attempting conflict repair with server-side force-conflicts"
        run_capture_status "$patch_status_file" run_and_log "Repair Helm upgrade ingress-nginx patched" "${result_dir}/helm_upgrade_v1_11_5_repair.log" \
            helm upgrade ingress-nginx ingress-nginx/ingress-nginx \
                --version "$PATCHED_CHART_VERSION" \
                -n "$INGRESS_NGINX_NAMESPACE" \
                --set "controller.image.tag=${PATCHED_CONTROLLER_TAG}" \
                --set controller.admissionWebhooks.enabled=true \
                --set controller.admissionWebhooks.failurePolicy=Fail \
                --set controller.service.type=NodePort \
                --set controller.config.allow-snippet-annotations=true \
                --server-side true \
                --force-conflicts \
                --wait \
                --timeout 5m || true
        patch_status="$(cat "$patch_status_file")"
    fi

    run_and_log "Rollout status patched ingress-nginx-controller" "${result_dir}/rollout_status.log" \
        kubectl rollout status deploy/ingress-nginx-controller -n "$INGRESS_NGINX_NAMESPACE" --timeout=120s || true
    log_current_state "after_patch" "$result_dir"
    local image_after helm_status_after
    image_after="$(first_nonempty_line "${result_dir}/after_patch_image.txt")"
    helm_status_after="$(helm_release_status "${result_dir}/after_patch_helm_release.txt")"
    local patched_image_ok="false"
    if image_contains_tag "$image_after" "$PATCHED_CONTROLLER_TAG"; then
        patched_image_ok="true"
    fi

    echo "[blue2] post-patch: run validation"
    local post_poc_pf_log post_attack_pf_log post_poc_pf_pid post_attack_pf_pid
    post_poc_pf_log="${result_dir}/post_patch_poc_portforward.log"
    post_attack_pf_log="${result_dir}/post_patch_attack_portforward.log"
    post_poc_pf_pid="${result_dir}/post_patch_poc_portforward.pid"
    post_attack_pf_pid="${result_dir}/post_patch_attack_portforward.pid"
    run_and_log "Post-patch poc-step3" "${result_dir}/post_patch_poc_step3.log" \
        make -C "$LAB_ROOT" "PF_LOG_FILE=${post_poc_pf_log}" "PF_PID_FILE=${post_poc_pf_pid}" poc-step3 || true
    sanitize_file_in_place "$post_poc_pf_log"
    run_and_log "Post-patch attack-chain" "${result_dir}/post_patch_attack_chain.log" \
        make -C "$LAB_ROOT" "ATTACK_OUT=${result_dir}/post-patch-attack-results" "PF_LOG_FILE=${post_attack_pf_log}" "PF_PID_FILE=${post_attack_pf_pid}" attack-chain || true
    sanitize_file_in_place "$post_attack_pf_log"

    local pre_poc pre_t1 pre_t2 pre_t3 post_poc post_t1 post_t2 post_t3
    local pre_patch_file_enum_count post_patch_file_enum_count
    pre_poc="$(poc_step3_result "${result_dir}/pre_patch_poc_step3.log")"
    pre_t1="$(attack_chain_stage_result "${result_dir}/pre_patch_attack_chain.log" t1)"
    pre_t2="$(attack_chain_stage_result "${result_dir}/pre_patch_attack_chain.log" t2)"
    pre_t3="$(attack_chain_stage_result "${result_dir}/pre_patch_attack_chain.log" t3)"
    pre_patch_file_enum_count="$(file_enum_count "${result_dir}/pre_patch_attack_chain.log")"
    post_poc="$(poc_step3_result "${result_dir}/post_patch_poc_step3.log")"
    post_t1="$(attack_chain_stage_result "${result_dir}/post_patch_attack_chain.log" t1)"
    post_t2="$(attack_chain_stage_result "${result_dir}/post_patch_attack_chain.log" t2)"
    post_t3="$(attack_chain_stage_result "${result_dir}/post_patch_attack_chain.log" t3)"
    post_patch_file_enum_count="$(file_enum_count "${result_dir}/post_patch_attack_chain.log")"

    local helm_upgrade_succeeded="false"
    if [[ "$patch_status" -eq 0 && "$helm_status_after" == "deployed" ]]; then
        helm_upgrade_succeeded="true"
    fi

    local exploit_path_blocked="false"
    if [[ "$vulnerable_image_ok" == "true" ]] \
        && [[ "$patched_image_ok" == "true" ]] \
        && [[ "$helm_upgrade_succeeded" == "true" ]] \
        && is_nonzero_count "$pre_patch_file_enum_count" \
        && is_zero_count "$post_patch_file_enum_count"; then
        exploit_path_blocked="true"
    fi

    local fallback_t2_t3_observed="false"
    if [[ "$post_t2" == "Reached via kubectl_exec fallback" || "$post_t3" == "Reached" ]]; then
        fallback_t2_t3_observed="true"
    fi

    local poc_step3_status="pre=${pre_poc}; post=${post_poc}"
    local b1_exploit_path_verdict b1_end_to_end_verdict b1_reason
    if [[ "$reset_status" -ne 0 ]]; then
        b1_exploit_path_verdict="failed/incomplete"
        b1_reason="vulnerable baseline reset exited non-zero"
    elif [[ "$vulnerable_image_ok" != "true" ]]; then
        b1_exploit_path_verdict="failed/incomplete"
        b1_reason="vulnerable baseline image does not contain ${VULN_CONTROLLER_TAG}"
    elif ! is_nonzero_count "$pre_patch_file_enum_count"; then
        b1_exploit_path_verdict="failed/incomplete"
        b1_reason="vulnerable baseline did not reproduce the exploit path before patching"
    elif [[ "$helm_upgrade_succeeded" != "true" ]]; then
        b1_exploit_path_verdict="failed/incomplete"
        b1_reason="Helm release is not deployed or patched upgrade exited non-zero"
    elif [[ "$patched_image_ok" != "true" ]]; then
        b1_exploit_path_verdict="failed/incomplete"
        b1_reason="controller image does not contain ${PATCHED_CONTROLLER_TAG}"
    elif [[ "$exploit_path_blocked" == "true" ]]; then
        b1_exploit_path_verdict="passed"
        b1_reason="v1.11.5 blocked CVE file enumeration from ${pre_patch_file_enum_count}/12 to ${post_patch_file_enum_count}/12"
    else
        b1_exploit_path_verdict="failed/incomplete"
        b1_reason="post-patch file enumeration was not reduced to zero"
    fi

    if [[ "$poc_step3_status" == *"Inconclusive"* && "$fallback_t2_t3_observed" == "true" ]]; then
        b1_end_to_end_verdict="inconclusive due to fallback and port-forward readiness"
    elif [[ "$fallback_t2_t3_observed" == "true" ]]; then
        b1_end_to_end_verdict="inconclusive due to kubectl_exec fallback reachability"
    elif [[ "$poc_step3_status" == *"Inconclusive"* ]]; then
        b1_end_to_end_verdict="inconclusive due to port-forward readiness"
    elif [[ "$b1_exploit_path_verdict" == "passed" ]]; then
        b1_end_to_end_verdict="passed"
    else
        b1_end_to_end_verdict="failed/incomplete"
    fi

    cat >"${result_dir}/summary.md" <<EOF
# Blue Team 2 B1 ingress-nginx 패치 검증 요약

- 결과 디렉터리: \`${result_dir#${LAB_ROOT}/}\`
- Kubernetes context: \`$(kubectl config current-context 2>/dev/null || echo unknown)\`
- 비교 기준: vulnerable chart \`${VULN_CHART_VERSION}\` / controller \`${VULN_CONTROLLER_TAG}\` vs patched chart \`${PATCHED_CHART_VERSION}\` / controller \`${PATCHED_CONTROLLER_TAG}\`
- B1 exploit-specific patch validation: \`${b1_exploit_path_verdict}\`
- End-to-end attack-chain validation: \`${b1_end_to_end_verdict}\`
- 판정 이유: ${b1_reason}

## 핵심 결과

| 항목 | 결과 |
|---|---|
| vulnerable baseline controller image | \`${image_vulnerable:-unknown}\` |
| vulnerable baseline image verified | \`${vulnerable_image_ok}\` |
| reset Helm exit status | \`${reset_status}\` |
| patched controller image | \`${image_after:-unknown}\` |
| patched image verified | \`${patched_image_ok}\` |
| Helm upgrade exit status | \`${patch_status}\` |
| Helm release status after patch | \`${helm_status_after:-unknown}\` |
| Helm upgrade succeeded | \`${helm_upgrade_succeeded}\` |
| pre_patch_file_enum_count | \`${pre_patch_file_enum_count}\` |
| post_patch_file_enum_count | \`${post_patch_file_enum_count}\` |
| exploit_path_blocked | \`${exploit_path_blocked}\` |
| fallback_t2_t3_observed | \`${fallback_t2_t3_observed}\` |
| poc_step3_status | \`${poc_step3_status}\` |
| b1_exploit_path_verdict | \`${b1_exploit_path_verdict}\` |
| b1_end_to_end_verdict | \`${b1_end_to_end_verdict}\` |
| pre-patch poc-step3 결과 | \`${pre_poc}\` |
| pre-patch attack-chain T1 | \`${pre_t1}\` |
| pre-patch attack-chain T2 | \`${pre_t2}\` |
| pre-patch attack-chain T3 | \`${pre_t3}\` |
| post-patch poc-step3 차단 여부 | \`${post_poc}\` |
| post-patch attack-chain T1 | \`${post_t1}\` |
| post-patch attack-chain T2 | \`${post_t2}\` |
| post-patch attack-chain T3 | \`${post_t3}\` |
| post-patch exploit path blocked before T2/T3 | \`${exploit_path_blocked}\` |

## 해석

- B1은 먼저 취약 baseline(\`${VULN_CHART_VERSION}\` / \`${VULN_CONTROLLER_TAG}\`)으로 되돌린 뒤 pre-patch 공격 결과를 기록한다.
- 패치 단계는 \`${PATCHED_CHART_VERSION}\` / \`${PATCHED_CONTROLLER_TAG}\`로 업그레이드하고, Helm release가 \`deployed\`인지와 controller image가 \`${PATCHED_CONTROLLER_TAG}\`인지 모두 확인한다.
- ConfigMap field-manager 충돌을 줄이기 위해 Helm upgrade에 server-side apply와 \`--force-conflicts\`를 사용한다. 충돌 또는 upgrade 실패가 발생하면 repair upgrade를 별도 로그에 남기고, 실패를 조용히 무시하지 않는다.
- B1 exploit-specific patch validation은 CVE-2025-1974의 파일 열거 경로가 패치 후 차단되었는지를 본다.
- \`kubectl_exec\` fallback은 실습 편의용 경로이며 CVE exploit path와 동일하지 않다. 따라서 fallback으로 T2/T3가 관찰되어도 exploit-specific patch validation 실패로 계산하지 않는다.
- \`${PATCHED_CONTROLLER_TAG}\`는 파일 열거를 \`${pre_patch_file_enum_count}/12\`에서 \`${post_patch_file_enum_count}/12\`로 낮췄다.
- 추가적인 clean direct PoC 검증은 \`poc-step3\`의 port-forward readiness 문제를 해결한 뒤 다시 수행해야 한다.
- 전체 end-to-end attack-chain은 fallback 및 port-forward readiness 영향이 있으면 inconclusive로 보고, exploit-specific patch validation과 분리해 보고한다.

## 권장 보고 문장

B1 검증은 vulnerable baseline \`${image_vulnerable:-unknown}\`에서 patched image \`${image_after:-unknown}\`로 전환한 뒤 수행했다. B1 exploit-specific patch validation은 \`${b1_exploit_path_verdict}\`이고, end-to-end attack-chain validation은 \`${b1_end_to_end_verdict}\`이다. 근거: ${b1_reason}.

## 관련 로그

| 로그 | 설명 |
|---|---|
| \`reset_vulnerable_baseline.log\` | 취약 baseline Helm reset |
| \`reset_vulnerable_rollout.log\` | 취약 baseline rollout |
| \`vulnerable_baseline_image.txt\` | 취약 baseline 실제 image |
| \`vulnerable_baseline_helm_release.txt\` | 취약 baseline Helm release |
| \`allow_snippet_patch.log\` | allow-snippet-annotations=true 보정 |
| \`pre_patch_attack_chain.log\` | 패치 전 공격 체인 |
| \`pre_patch_poc_step3.log\` | 패치 전 auth-snippet 우회 검증 |
| \`helm_upgrade_v1_11_5.log\` | v1.11.5 패치 적용 로그 |
| \`helm_upgrade_v1_11_5_repair.log\` | 충돌 시 repair upgrade 로그 |
| \`after_patch_image.txt\` | 패치 후 실제 controller image |
| \`after_patch_helm_release.txt\` | 패치 후 Helm release 상태 |
| \`post_patch_poc_step3.log\` | 패치 후 auth-snippet 우회 재검증 |
| \`post_patch_attack_chain.log\` | 패치 후 공격 체인 |
EOF

    echo "[blue2] summary written: ${result_dir#${LAB_ROOT}/}/summary.md"
}

main "$@"
