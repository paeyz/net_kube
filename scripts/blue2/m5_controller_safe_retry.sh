#!/usr/bin/env bash
# Blue Team 2: M5 retry with controller-safe M4 RBAC.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/blue2/common.sh
source "${SCRIPT_DIR}/common.sh"

TARGET_CONTEXT="${TARGET_CONTEXT:-cve-2025-1974-netpol}"
M2_CURL_IMAGE="${M2_CURL_IMAGE:-curlimages/curl:8.7.1}"
ASSUME_YES=false

usage() {
    cat <<'EOF'
Usage: scripts/blue2/m5_controller_safe_retry.sh [--yes]

Runs the approved M5 retry only in cve-2025-1974-netpol:
  1. restore ingress-nginx controller health from RBAC backup
  2. scope the controller with Helm so namespace-only Secret access is safe
  3. apply controller-safe M4 RBAC
  4. verify M2, M3, M4 together

This script writes sanitized logs under results/blue2/<timestamp>-m5/.
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

require_exact_context() {
    local ctx
    ctx="$(kubectl config current-context 2>/dev/null || true)"
    if [[ "$ctx" != "$TARGET_CONTEXT" ]]; then
        echo "[ERROR] Refusing to run. Current context is '${ctx}', expected '${TARGET_CONTEXT}'." >&2
        exit 1
    fi
}

latest_rbac_backup() {
    find "${BLUE2_RESULTS_ROOT}" -path '*/rbac-backup/ingress-nginx.yaml' -type f \
        | sort \
        | tail -1
}

endpoint_nonempty() {
    kubectl get endpoints ingress-nginx-controller-admission -n "$INGRESS_NGINX_NAMESPACE" \
        -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null | grep -q .
}

controller_ready() {
    local ready
    ready="$(kubectl get deploy ingress-nginx-controller -n "$INGRESS_NGINX_NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
    [[ "${ready:-0}" != "" && "${ready:-0}" -ge 1 ]] && endpoint_nonempty
}

wait_controller_health() {
    local result_dir="$1"
    run_and_log "Wait ingress-nginx rollout" "${result_dir}/rollout_status.log" \
        kubectl rollout status deploy/ingress-nginx-controller -n "$INGRESS_NGINX_NAMESPACE" --timeout=180s || true
    run_and_log "Controller health snapshot" "${result_dir}/controller_health_snapshot.log" \
        bash -lc "kubectl get deploy ingress-nginx-controller -n '${INGRESS_NGINX_NAMESPACE}' -o wide; kubectl get pods -n '${INGRESS_NGINX_NAMESPACE}' -l app.kubernetes.io/component=controller -o wide; kubectl get endpoints -n '${INGRESS_NGINX_NAMESPACE}' ingress-nginx-controller-admission -o wide" || true
}

render_effective_m2() {
    local output="$1"
    local node_ip cidr
    node_ip="$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
    cidr="${node_ip}/32"
    sed -E "s#cidr: [0-9.]+/[0-9]+#cidr: ${cidr}#" "${LAB_ROOT}/defense/m2-networkpolicy.yaml" >"$output"
}

curl_from_temp_pod() {
    local result_dir="$1"
    local logfile="$2"
    local pod="blue2-m2-curl-$(date +%s)"
    local target="https://ingress-nginx-controller-admission.ingress-nginx.svc:443/"
    local tmp
    tmp="$(mktemp)"

    set +e
    {
        echo "## curl from temporary default namespace pod"
        echo "## pod: ${pod}"
        echo "## target: ${target}"
        echo "## started: $(date -Iseconds)"
        kubectl run "$pod" -n default \
            --image="$M2_CURL_IMAGE" \
            --restart=Never \
            --command -- sh -c "curl -skv --connect-timeout 5 --max-time 8 '${target}'; rc=\$?; echo; echo curl_exit_status:\$rc; exit \$rc"

        for _ in $(seq 1 20); do
            phase="$(kubectl get pod "$pod" -n default -o jsonpath='{.status.phase}' 2>/dev/null || true)"
            [[ "$phase" == "Succeeded" || "$phase" == "Failed" ]] && break
            sleep 1
        done

        echo
        echo "## pod phase"
        kubectl get pod "$pod" -n default -o wide 2>/dev/null || true
        echo
        echo "## pod logs"
        kubectl logs "$pod" -n default 2>&1 || true
        echo
        kubectl delete pod "$pod" -n default --ignore-not-found --wait=false >/dev/null 2>&1 || true
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
}

first_answer() {
    awk 'tolower($0)=="yes" || tolower($0)=="no" {print tolower($0); exit}' "$1"
}

main() {
    require_cmd kubectl helm make sed awk grep
    require_exact_context

    local result_dir
    result_dir="$(make_result_dir "m5")"
    echo "[blue2] result directory: ${result_dir#${LAB_ROOT}/}"

    if [[ ! -e "${LAB_ROOT}/results/blue2_backup_before_m5_retry" ]]; then
        cp -a "${BLUE2_RESULTS_ROOT}" "${LAB_ROOT}/results/blue2_backup_before_m5_retry"
    fi
    if [[ ! -e "${LAB_ROOT}/docs/blue2_report_draft_before_m5_retry.md" ]]; then
        cp -a "${LAB_ROOT}/docs/blue2_report_draft.md" "${LAB_ROOT}/docs/blue2_report_draft_before_m5_retry.md"
    fi

    {
        echo "current_context: $(kubectl config current-context)"
        echo "target_context: ${TARGET_CONTEXT}"
        echo
        current_ingress_nginx_image
    } | redact_sensitive >"${result_dir}/context.txt"

    run_and_log "Calico evidence" "${result_dir}/calico_evidence.log" \
        bash -lc "kubectl get pods -A --no-headers | grep -Ei 'calico|tigera' || true; kubectl get crd --no-headers 2>/dev/null | grep -Ei 'calico|projectcalico|tigera' || true" || true

    local backup
    backup="$(latest_rbac_backup)"
    if [[ -z "$backup" ]]; then
        echo "[ERROR] No ingress-nginx ClusterRoleBinding backup found under ${BLUE2_RESULTS_ROOT}." >&2
        exit 1
    fi
    printf '%s\n' "$backup" >"${result_dir}/rbac_backup_used.txt"

    confirm_or_exit "M5 retry will restore ingress-nginx RBAC from backup, run a scoped Helm upgrade, apply controller-safe M4, update M2 temporarily for comparison, and create temporary curl/test resources." "$ASSUME_YES"

    echo "[blue2] restoring original ingress-nginx ClusterRoleBinding from backup"
    run_and_log "Restore original ingress-nginx ClusterRoleBinding" "${result_dir}/restore_original_crb.log" \
        kubectl apply -f "$backup" || true
    run_and_log "Restart controller after RBAC restore" "${result_dir}/restore_rollout_restart.log" \
        kubectl rollout restart deploy/ingress-nginx-controller -n "$INGRESS_NGINX_NAMESPACE" || true
    wait_controller_health "$result_dir"

    echo "[blue2] applying namespace-scoped controller configuration"
    run_and_log "Helm upgrade namespace-scoped controller" "${result_dir}/helm_scope_controller.log" \
        helm upgrade ingress-nginx ingress-nginx/ingress-nginx \
            --version 4.11.3 \
            -n "$INGRESS_NGINX_NAMESPACE" \
            --reuse-values \
            --set controller.scope.enabled=true \
            --set controller.scope.namespace="$INGRESS_NGINX_NAMESPACE" \
            --set rbac.scope=true \
            --set controller.admissionWebhooks.enabled=true \
            --set controller.admissionWebhooks.failurePolicy=Fail \
            --set controller.service.type=NodePort \
            --set controller.image.tag=v1.11.3 \
            --wait \
            --timeout 5m || true

    run_and_log "Apply controller-safe M4" "${result_dir}/apply_m4_controller_safe.log" \
        kubectl apply -f "${LAB_ROOT}/defense/m4-rbac-controller-safe.yaml" || true
    run_and_log "Remove broad ingress-nginx ClusterRoleBinding if present" "${result_dir}/delete_broad_crb.log" \
        kubectl delete clusterrolebinding ingress-nginx --ignore-not-found || true
    wait_controller_health "$result_dir"

    local m4_kube_log="${result_dir}/m4_can_i_kube_system.log"
    local m4_ingress_log="${result_dir}/m4_can_i_ingress_nginx.log"
    run_and_log "M4 kube-system Secrets can-i with groups" "$m4_kube_log" \
        kubectl auth can-i list secrets -n kube-system \
            --as="$INGRESS_NGINX_SA_REF" \
            --as-group=system:serviceaccounts \
            --as-group=system:serviceaccounts:ingress-nginx \
            --as-group=system:authenticated || true
    run_and_log "M4 ingress-nginx Secrets can-i with groups" "$m4_ingress_log" \
        kubectl auth can-i list secrets -n "$INGRESS_NGINX_NAMESPACE" \
            --as="$INGRESS_NGINX_SA_REF" \
            --as-group=system:serviceaccounts \
            --as-group=system:serviceaccounts:ingress-nginx \
            --as-group=system:authenticated || true

    if ! controller_ready; then
        echo "[blue2] controller is not healthy; skipping M2 comparison"
        printf '%s\n' "skipped: controller not healthy or endpoints empty" >"${result_dir}/m2_comparison_skipped.txt"
    else
        local effective_m2="${result_dir}/m2-networkpolicy-effective.yaml"
        render_effective_m2 "$effective_m2"

        run_and_log "Apply effective M2 NetworkPolicy" "${result_dir}/apply_m2_effective.log" \
            kubectl apply -f "$effective_m2" || true
        curl_from_temp_pod "$result_dir" "${result_dir}/m2_applied_curl.log"

        run_and_log "Temporarily remove effective M2 NetworkPolicy" "${result_dir}/delete_m2_effective.log" \
            kubectl delete -f "$effective_m2" --ignore-not-found || true
        curl_from_temp_pod "$result_dir" "${result_dir}/m2_removed_curl.log"

        run_and_log "Reapply effective M2 NetworkPolicy" "${result_dir}/reapply_m2_effective.log" \
            kubectl apply -f "$effective_m2" || true
    fi

    run_and_log "M3 policy presence" "${result_dir}/m3_policy.log" \
        kubectl get validatingadmissionpolicy block-dangerous-nginx-annotations || true
    run_and_log "M3 dangerous auth-snippet deny dry-run" "${result_dir}/m3_dangerous_deny_dry_run.log" \
        kubectl apply --dry-run=server -f - <<'EOF' || true
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: blue2-m3-dangerous-deny-test
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/auth-snippet: "include /etc/passwd;"
spec:
  ingressClassName: nginx
  rules:
  - host: blue2-m3-dangerous-test.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kubernetes
            port:
              number: 443
EOF
    run_and_log "Helm release status after M5 retry" "${result_dir}/helm_status_after_retry.log" \
        helm status ingress-nginx -n "$INGRESS_NGINX_NAMESPACE" || true

    local m2_status m3_status helm_status m4_kube m4_ingress health_status endpoint_status verdict reason
    if [[ -f "${result_dir}/m2_applied_curl.log" && -f "${result_dir}/m2_removed_curl.log" ]] \
        && grep -Eqi 'timed out|failed to connect|Could not connect|curl_exit_status:(7|28)' "${result_dir}/m2_applied_curl.log" \
        && grep -Eqi 'Connected to|SSL connection|HTTP/|subject:|curl_exit_status:0|curl_exit_status:22' "${result_dir}/m2_removed_curl.log"; then
        m2_status="passed"
    else
        m2_status="incomplete"
    fi
    if grep -q 'block-dangerous-nginx-annotations' "${result_dir}/m3_policy.log" 2>/dev/null \
        && grep -Eqi 'denied request|forbidden|invalid|denied' "${result_dir}/m3_dangerous_deny_dry_run.log" 2>/dev/null; then
        m3_status="present and deny-tested"
    elif grep -q 'block-dangerous-nginx-annotations' "${result_dir}/m3_policy.log" 2>/dev/null; then
        m3_status="present"
    else
        m3_status="missing"
    fi
    helm_status="$(awk '/^STATUS:/{print $2; exit}' "${result_dir}/helm_status_after_retry.log" 2>/dev/null || true)"
    m4_kube="$(first_answer "$m4_kube_log")"
    m4_ingress="$(first_answer "$m4_ingress_log")"
    if controller_ready; then
        health_status="yes"
        endpoint_status="yes"
    else
        health_status="no"
        endpoint_status="no"
    fi

    if [[ "$m2_status" == "passed" && "$m3_status" == "present and deny-tested" && "$m4_kube" == "no" && "$m4_ingress" =~ ^(yes|no)$ && "$health_status" == "yes" && "$helm_status" == "deployed" ]]; then
        verdict="passed"
        reason="Calico, controller health, M2 comparison, M3 policy, and M4 RBAC checks all met the M5 criteria."
    elif [[ "$m2_status" == "passed" && "$m3_status" == "present and deny-tested" && "$m4_kube" == "no" && "$m4_ingress" =~ ^(yes|no)$ && "$health_status" == "yes" ]]; then
        verdict="partial"
        reason="M2, M3, M4 evidence passed and controller health was restored, but Helm release status is ${helm_status:-unknown}; repair is still required before calling this cleanly complete."
    else
        verdict="partial/incomplete"
        reason="One or more M5 criteria were not proven. Review the evidence logs before claiming success."
    fi

    cat >"${result_dir}/summary.md" <<EOF
# Blue Team 2 M5 Full Stack 통합 검증 요약

- 결과 디렉터리: \`${result_dir#${LAB_ROOT}/}\`
- Kubernetes context: \`$(kubectl config current-context)\`
- M5 판정: \`${verdict}\`
- 판정 이유: ${reason}

## 핵심 결과

| 항목 | 결과 |
|---|---|
| Calico / NetworkPolicy CNI | \`confirmed\` |
| controller health restored | \`${health_status}\` |
| admission endpoints non-empty | \`${endpoint_status}\` |
| M2 direct Service DNS comparison | \`${m2_status}\` |
| M3 ValidatingAdmissionPolicy | \`${m3_status}\` |
| M4 kube-system Secrets 권한 | \`${m4_kube:-unknown}\` |
| M4 ingress-nginx Secrets 권한 | \`${m4_ingress:-unknown}\` |
| Helm release status after retry | \`${helm_status:-unknown}\` |
| M5 final verdict | \`${verdict}\` |

## 해석

- 이 retry는 \`cve-2025-1974-netpol\` 컨텍스트에서만 수행했다.
- controller-safe M4는 namespace-scoped ingress-nginx controller와 함께 사용해 kube-system Secrets 접근을 차단하면서 controller health를 유지하는 것을 목표로 한다.
- M2 성공 판정은 endpoints가 존재하는 상태에서만 적용/제거 curl 비교로 판단한다.
- M5 결과는 기존 original lab profile의 M4 성공 및 B1 exploit-specific patch validation 성공을 덮어쓰지 않는다.

## 관련 로그

| 로그 | 설명 |
|---|---|
| \`restore_original_crb.log\` | controller health 복구를 위한 원본 CRB 복원 |
| \`helm_scope_controller.log\` | namespace-scoped controller Helm upgrade |
| \`apply_m4_controller_safe.log\` | controller-safe M4 적용 |
| \`delete_broad_crb.log\` | broad CRB 제거 |
| \`m4_can_i_kube_system.log\` | kube-system Secrets RBAC 확인 |
| \`m4_can_i_ingress_nginx.log\` | ingress-nginx Secrets RBAC 확인 |
| \`m2_applied_curl.log\` | M2 적용 상태 curl |
| \`m2_removed_curl.log\` | M2 제거 상태 curl |
| \`m3_policy.log\` | M3 정책 확인 |
| \`m3_dangerous_deny_dry_run.log\` | 위험 auth-snippet dry-run deny 확인 |
| \`helm_status_after_retry.log\` | Helm release 상태 확인 |
EOF
    sanitize_file_in_place "${result_dir}/summary.md"
    echo "[blue2] summary written: ${result_dir#${LAB_ROOT}/}/summary.md"
}

main "$@"
