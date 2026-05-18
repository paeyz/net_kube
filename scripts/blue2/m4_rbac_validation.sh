#!/usr/bin/env bash
# Blue Team 2: M4 RBAC least-privilege validation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/blue2/common.sh
source "${SCRIPT_DIR}/common.sh"

ASSUME_YES=false
REMOVE_BROAD_CRB=false

usage() {
    cat <<'EOF'
Usage: scripts/blue2/m4_rbac_validation.sh [--yes] [--remove-broad-crb]

Runs local Minikube-only M4 RBAC validation and writes sanitized logs under
results/blue2/<timestamp>-m4/.

  --yes                Proceed without an interactive confirmation.
  --remove-broad-crb   Back up and delete broad ClusterRoleBindings for the
                       ingress-nginx ServiceAccount, except the M4 minimal CRB.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes)
            ASSUME_YES=true
            shift
            ;;
        --remove-broad-crb)
            REMOVE_BROAD_CRB=true
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

append_group_can_i_check() {
    local namespace="$1"
    local include_groups="$2"
    local logfile="$3"
    local out status answer

    local cmd_display
    cmd_display="kubectl auth can-i list secrets -n ${namespace} --as=${INGRESS_NGINX_SA_REF}"

    set +e
    if [[ "$include_groups" == "true" ]]; then
        cmd_display="${cmd_display} --as-group=system:serviceaccounts --as-group=system:serviceaccounts:${INGRESS_NGINX_NAMESPACE} --as-group=system:authenticated"
        out="$(kubectl auth can-i list secrets -n "$namespace" \
            --as="$INGRESS_NGINX_SA_REF" \
            --as-group=system:serviceaccounts \
            --as-group="system:serviceaccounts:${INGRESS_NGINX_NAMESPACE}" \
            --as-group=system:authenticated 2>&1)"
    else
        out="$(kubectl auth can-i list secrets -n "$namespace" --as="$INGRESS_NGINX_SA_REF" 2>&1)"
    fi
    status=$?
    set -e

    {
        echo
        echo "## RBAC can-i check"
        echo "\$ ${cmd_display}"
        echo
        printf '%s\n' "$out"
        echo
        echo "## exit_status: ${status}"
    } | redact_sensitive >>"$logfile"

    answer="$(printf '%s\n' "$out" | awk 'tolower($0)=="yes" || tolower($0)=="no" {print tolower($0); exit}')"
    if [[ -z "$answer" ]]; then
        answer="error"
    fi
    printf '%s\n' "$answer"
}

write_group_bindings_to_sensitive_roles() {
    local logfile="$1"
    local tmp
    tmp="$(mktemp)"

    {
        echo -e "scope\tnamespace\tbinding_kind\tbinding_name\trole_kind\trole_name\tsubjects"
        kubectl get clusterrolebindings \
            -o jsonpath='{range .items[*]}{.metadata.name}{"|ClusterRoleBinding|"}{.roleRef.kind}{"|"}{.roleRef.name}{"|"}{range .subjects[*]}{.kind}{":"}{.namespace}{":"}{.name}{";"}{end}{"\n"}{end}' 2>/dev/null \
            | while IFS='|' read -r binding kind role_kind role_name subjects; do
                [[ -z "$binding" ]] && continue
                if [[ "$subjects" =~ (Group::system:serviceaccounts\;|Group::system:serviceaccounts:${INGRESS_NGINX_NAMESPACE}\;|Group::system:authenticated\;|ServiceAccount:${INGRESS_NGINX_NAMESPACE}:${INGRESS_NGINX_SERVICEACCOUNT}\;) ]]; then
                    printf 'cluster\t-\t%s\t%s\t%s\t%s\t%s\n' "$kind" "$binding" "$role_kind" "$role_name" "$subjects"
                fi
            done
        kubectl get rolebindings -A \
            -o jsonpath='{range .items[*]}{.metadata.namespace}{"|"}{.metadata.name}{"|RoleBinding|"}{.roleRef.kind}{"|"}{.roleRef.name}{"|"}{range .subjects[*]}{.kind}{":"}{.namespace}{":"}{.name}{";"}{end}{"\n"}{end}' 2>/dev/null \
            | while IFS='|' read -r namespace binding kind role_kind role_name subjects; do
                [[ -z "$binding" ]] && continue
                if [[ "$subjects" =~ (Group::system:serviceaccounts\;|Group::system:serviceaccounts:${INGRESS_NGINX_NAMESPACE}\;|Group::system:authenticated\;|ServiceAccount:${INGRESS_NGINX_NAMESPACE}:${INGRESS_NGINX_SERVICEACCOUNT}\;) ]]; then
                    printf 'namespace\t%s\t%s\t%s\t%s\t%s\t%s\n' "$namespace" "$kind" "$binding" "$role_kind" "$role_name" "$subjects"
                fi
            done
    } >"$tmp"

    redact_sensitive <"$tmp" >"$logfile"
    rm -f "$tmp"
}

list_broad_clusterrolebindings() {
    kubectl get clusterrolebindings \
        -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{.roleRef.kind}{"|"}{.roleRef.name}{"|"}{range .subjects[*]}{.kind}{":"}{.namespace}{":"}{.name}{";"}{end}{"\n"}{end}' 2>/dev/null \
        | while IFS='|' read -r name role_kind role_name subjects; do
            [[ -z "$name" ]] && continue
            if [[ "$subjects" == *"ServiceAccount:${INGRESS_NGINX_NAMESPACE}:${INGRESS_NGINX_SERVICEACCOUNT};"* \
                && "$name" != "$M4_MINIMAL_CLUSTERROLEBINDING" ]]; then
                printf '%s\t%s\t%s\n' "$name" "$role_kind" "$role_name"
            fi
        done
}

log_context() {
    local logfile="$1"
    {
        echo "# Kubernetes context"
        echo "current_context: $(kubectl config current-context 2>/dev/null || true)"
        echo "cluster_server: $(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)"
        echo
        echo "# ingress-nginx namespace"
        kubectl get namespace "$INGRESS_NGINX_NAMESPACE" -o wide 2>&1 || true
        echo
        echo "# controller image"
        current_ingress_nginx_image
    } | redact_sensitive >"$logfile"
}

token_test_result() {
    local logfile="$1"
    if grep -Eqi 'authorization_decision:[[:space:]]*no\b|Forbidden|forbidden' "$logfile"; then
        echo "Forbidden"
    elif grep -Eqi 'authorization_decision:[[:space:]]*yes\b|^NAME[[:space:]]+TYPE|No resources found|kubernetes.io/' "$logfile"; then
        echo "Allowed"
    elif grep -Eqi 'token unavailable|test skipped' "$logfile"; then
        echo "Skipped"
    else
        echo "Unknown"
    fi
}

attack_t2_result() {
    local logfile="$1"
    if grep -Eqi '토큰 추출 성공|ServiceAccount JWT|T2 토큰 추출[[:space:]]+— 성공' "$logfile"; then
        echo "Observed"
    elif grep -Eqi '토큰 추출 실패|T2.*실패|스킵 \(토큰 없음\)' "$logfile"; then
        echo "Not observed"
    else
        echo "Unknown"
    fi
}

main() {
    require_cmd kubectl helm make

    local result_dir
    result_dir="$(make_result_dir "m4")"
    echo "[blue2] result directory: ${result_dir#${LAB_ROOT}/}"

    check_kube_context
    if ! kubectl get namespace "$INGRESS_NGINX_NAMESPACE" >/dev/null 2>&1; then
        echo "[ERROR] namespace not found: ${INGRESS_NGINX_NAMESPACE}" >&2
        exit 1
    fi
    log_context "${result_dir}/context.txt"

    confirm_or_exit "This will run defense-restore, attack-chain, apply M4 RBAC, and run post-M4 validation against the current local Minikube context." "$ASSUME_YES"

    echo "[blue2] baseline: restore defenses, then run attack-chain"
    run_and_log "Baseline defense restore" "${result_dir}/baseline_defense_restore.log" \
        bash -c "cd '$LAB_ROOT' && make defense-restore || true" || true
    local baseline_pf_log
    baseline_pf_log="${result_dir}/baseline_portforward.log"
    run_and_log "Baseline attack-chain" "${result_dir}/baseline_attack_chain.log" \
        make -C "$LAB_ROOT" "ATTACK_OUT=${result_dir}/baseline-attack-results" "PF_LOG_FILE=${baseline_pf_log}" attack-chain || true
    sanitize_file_in_place "$baseline_pf_log"

    local before_kube_system before_ingress
    before_kube_system="$(capture_can_i kube-system "${result_dir}/rbac_before_kube_system.log")"
    before_ingress="$(capture_can_i "$INGRESS_NGINX_NAMESPACE" "${result_dir}/rbac_before_ingress_nginx.log")"

    echo "[blue2] applying M4 RBAC policy"
    run_and_log "Apply M4 RBAC" "${result_dir}/apply_m4.log" make -C "$LAB_ROOT" defense-m4 || true

    local broad_tmp broad_file broad_count broad_after_count
    broad_tmp="$(mktemp)"
    list_broad_clusterrolebindings >"$broad_tmp" || true
    broad_file="${result_dir}/broad_clusterrolebindings_after_m4.tsv"
    broad_count="$(wc -l <"$broad_tmp" | tr -d ' ')"
    broad_after_count="$broad_count"
    {
        echo -e "name\trole_kind\trole_name"
        cat "$broad_tmp"
    } | redact_sensitive >"$broad_file"

    if [[ "$broad_count" -gt 0 ]]; then
        echo "[WARN] broad ClusterRoleBindings still bind ${INGRESS_NGINX_SA_REF}; see ${broad_file#${LAB_ROOT}/}"
        if [[ "$REMOVE_BROAD_CRB" == "true" ]]; then
            local backup_dir
            backup_dir="${result_dir}/rbac-backup"
            mkdir -p "$backup_dir"
            while IFS=$'\t' read -r crb _role_kind _role_name; do
                [[ -z "$crb" ]] && continue
                local safe_name
                safe_name="$(printf '%s' "$crb" | tr -c 'A-Za-z0-9_.-' '_')"
                kubectl get clusterrolebinding "$crb" -o yaml 2>&1 \
                    | redact_sensitive >"${backup_dir}/${safe_name}.yaml"
                run_and_log "Delete broad ClusterRoleBinding ${crb}" "${result_dir}/delete_crb_${safe_name}.log" \
                    kubectl delete clusterrolebinding "$crb" || true
            done <"$broad_tmp"
            list_broad_clusterrolebindings | redact_sensitive >"${result_dir}/broad_clusterrolebindings_after_removal.tsv" || true
            broad_after_count="$(list_broad_clusterrolebindings | wc -l | tr -d ' ')"
        fi
    fi
    rm -f "$broad_tmp"

    local after_kube_system after_ingress
    after_kube_system="$(capture_can_i kube-system "${result_dir}/rbac_after_kube_system.log")"
    after_ingress="$(capture_can_i "$INGRESS_NGINX_NAMESPACE" "${result_dir}/rbac_after_ingress_nginx.log")"

    local group_rbac_file group_kube_system_plain group_kube_system_with_groups group_ingress_with_groups
    group_rbac_file="${result_dir}/group_rbac_checks.txt"
    {
        echo "# Group-aware RBAC checks"
        echo "Generated: $(date -Iseconds)"
        echo "These checks do not read Secret values."
    } >"$group_rbac_file"
    group_kube_system_plain="$(append_group_can_i_check kube-system false "$group_rbac_file")"
    group_kube_system_with_groups="$(append_group_can_i_check kube-system true "$group_rbac_file")"
    group_ingress_with_groups="$(append_group_can_i_check "$INGRESS_NGINX_NAMESPACE" true "$group_rbac_file")"
    write_group_bindings_to_sensitive_roles "${result_dir}/group_bindings_to_sensitive_roles.tsv"

    local pod token
    pod="$(get_ingress_controller_pod || true)"
    token=""
    if [[ -n "$pod" ]]; then
        set +e
        token="$(kubectl exec -n "$INGRESS_NGINX_NAMESPACE" "$pod" -- cat "$INGRESS_NGINX_TOKEN_PATH" 2>/dev/null)"
        local token_status=$?
        set -e
        if [[ "$token_status" -eq 0 && -n "$token" ]]; then
            echo "[blue2] ingress-nginx ServiceAccount token loaded into memory only; it will not be printed."
            printf 'token_extraction: success\npod: %s\n' "$pod" >"${result_dir}/token_extraction_status.txt"
        else
            echo "[WARN] failed to read ServiceAccount token from controller pod."
            printf 'token_extraction: failed\npod: %s\n' "$pod" >"${result_dir}/token_extraction_status.txt"
            token=""
        fi
    else
        echo "[WARN] ingress-nginx controller pod not found; token-based validation skipped."
        printf 'token_extraction: skipped\nreason: controller pod not found\n' >"${result_dir}/token_extraction_status.txt"
    fi

    safe_kubectl_token_test "$token" kube-system "${result_dir}/isolated_token_test_kube_system.log" || true
    safe_kubectl_token_test "$token" "$INGRESS_NGINX_NAMESPACE" "${result_dir}/isolated_token_test_ingress_nginx.log" || true
    unset token

    echo "[blue2] post-M4: run attack-chain"
    local post_pf_log
    post_pf_log="${result_dir}/post_m4_portforward.log"
    run_and_log "Post-M4 attack-chain" "${result_dir}/post_m4_attack_chain.log" \
        make -C "$LAB_ROOT" "ATTACK_OUT=${result_dir}/post-m4-attack-results" "PF_LOG_FILE=${post_pf_log}" attack-chain || true
    sanitize_file_in_place "$post_pf_log"

    local kube_system_token_result ingress_token_result t2_after t3_limited m4_verdict m4_reason
    kube_system_token_result="$(token_test_result "${result_dir}/isolated_token_test_kube_system.log")"
    ingress_token_result="$(token_test_result "${result_dir}/isolated_token_test_ingress_nginx.log")"
    t2_after="$(attack_t2_result "${result_dir}/post_m4_attack_chain.log")"
    if [[ "$kube_system_token_result" == "Forbidden" ]]; then
        t3_limited="Yes"
        m4_verdict="Passed"
        m4_reason="isolated token test denied kube-system Secrets access"
    elif [[ "$after_kube_system" == "no" && "$kube_system_token_result" == "Allowed" ]]; then
        t3_limited="Contradiction"
        m4_verdict="Contradiction"
        m4_reason="impersonation without groups says no, but isolated token test says allowed"
    elif [[ "$group_kube_system_with_groups" == "yes" ]]; then
        t3_limited="No"
        m4_verdict="Failed/incomplete"
        m4_reason="group-level RBAC grants kube-system Secrets access"
    elif [[ "$kube_system_token_result" == "Allowed" ]]; then
        t3_limited="No"
        m4_verdict="Failed/incomplete"
        m4_reason="isolated token test still allowed kube-system Secrets access"
    else
        t3_limited="Unknown"
        m4_verdict="Incomplete"
        m4_reason="kube-system token authorization result was not conclusive"
    fi

    cat >"${result_dir}/summary.md" <<EOF
# Blue Team 2 M4 RBAC 최소 권한화 검증 요약

- 결과 디렉터리: \`${result_dir#${LAB_ROOT}/}\`
- Kubernetes context: \`$(kubectl config current-context 2>/dev/null || echo unknown)\`
- ServiceAccount: \`${INGRESS_NGINX_SA_REF}\`
- 광범위 ClusterRoleBinding 잔존 개수: \`${broad_count}\`
- 광범위 ClusterRoleBinding 제거 후 잔존 개수: \`${broad_after_count}\`
- 광범위 ClusterRoleBinding 제거 옵션 사용: \`${REMOVE_BROAD_CRB}\`
- M4 판정: \`${m4_verdict}\`
- 판정 이유: ${m4_reason}

## 핵심 결과

| 항목 | 결과 |
|---|---|
| M4 적용 전 kube-system Secrets list 권한 | \`${before_kube_system}\` |
| M4 적용 후 kube-system Secrets list 권한 | \`${after_kube_system}\` |
| M4 적용 전 ingress-nginx Secrets list 권한 | \`${before_ingress}\` |
| M4 적용 후 ingress-nginx Secrets list 권한 | \`${after_ingress}\` |
| 그룹 포함 kube-system Secrets list 권한 | \`${group_kube_system_with_groups}\` |
| 그룹 포함 ingress-nginx Secrets list 권한 | \`${group_ingress_with_groups}\` |
| 격리 토큰으로 kube-system Secrets 권한 | \`${kube_system_token_result}\` |
| 격리 토큰으로 ingress-nginx Secrets 권한 | \`${ingress_token_result}\` |
| M4 이후 T2 토큰 접근 관찰 | \`${t2_after}\` |
| M4 이후 T3 lateral movement 제한 | \`${t3_limited}\` |

## 해석

- M4는 CVE-2025-1974 자체의 토큰 파일 접근(T2)을 반드시 막는 방어가 아니다.
- M4의 성공 기준은 탈취된 ingress-nginx ServiceAccount 토큰으로 \`kube-system\` Secrets 접근이 \`Forbidden\` 또는 \`no\`가 되는 것이다.
- \`ingress-nginx\` 네임스페이스 권한은 TLS Secret 등 운영 필요성 때문에 남아 있을 수 있으며, 이는 blast radius가 네임스페이스 안으로 제한되었는지 확인하는 지표다.
- D3는 토큰 파일 접근을 계속 탐지할 수 있다. D4는 Kubernetes API 접근 시도를 보여주되, M4 이후에는 \`Forbidden\` 결과가 기대된다.

## 권장 보고 문장

M4 RBAC 최소 권한화 적용 후 ingress-nginx ServiceAccount의 kube-system Secrets 접근은 \`${after_kube_system}\`로 제한되었으며, 토큰 탈취 가능성은 남더라도 탈취 토큰의 lateral movement blast radius가 축소되었다.

## 관련 로그

| 로그 | 설명 |
|---|---|
| \`baseline_attack_chain.log\` | M0 취약 baseline 공격 체인 |
| \`baseline_portforward.log\` | baseline port-forward 로그 |
| \`rbac_before_kube_system.log\` | M4 전 kube-system RBAC 확인 |
| \`rbac_after_kube_system.log\` | M4 후 kube-system RBAC 확인 |
| \`group_rbac_checks.txt\` | 그룹 포함 RBAC 진단 |
| \`group_bindings_to_sensitive_roles.tsv\` | 관련 그룹/SA 바인딩 진단 |
| \`isolated_token_test_kube_system.log\` | 격리 kubeconfig 기반 kube-system 토큰 권한 결과 |
| \`isolated_token_test_ingress_nginx.log\` | 격리 kubeconfig 기반 ingress-nginx 토큰 권한 결과 |
| \`post_m4_attack_chain.log\` | M4 이후 공격 체인 재검증 |
| \`post_m4_portforward.log\` | M4 이후 port-forward 로그 |
| \`broad_clusterrolebindings_after_m4.tsv\` | M4 후 남아 있는 광범위 CRB |
EOF

    echo "[blue2] summary written: ${result_dir#${LAB_ROOT}/}/summary.md"
}

main "$@"
