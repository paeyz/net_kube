# Blue Team 2 M5 Full Stack 통합 검증 진단 요약

- 결과 디렉터리: `results/blue2/m5-diagnostics-20260518T222322+0900`
- Kubernetes context: `cve-2025-1974-netpol`
- M5 판정: `보류 / 환경 문제`
- 판정 이유: ingress-nginx controller가 CrashLoopBackOff 상태이고 admission endpoint가 비어 있어 M2 직접 Service DNS 비교를 해석할 수 없다.

## 핵심 결과

| 항목 | 결과 |
|---|---|
| Calico / NetworkPolicy CNI | `확인됨` |
| controller health restored | `no` |
| admission endpoints non-empty | `no` |
| M2 direct Service DNS comparison | `skipped: endpoints empty` |
| Docker attacker pod validation | `previous attempt not counted as M2 proof` |
| M3 ValidatingAdmissionPolicy | `present` |
| M4 kube-system Secrets 권한 | `denied` |
| M4 ingress-nginx Secrets 권한 | `allowed` |
| D1/D2/D3/D4 mapping | `conceptually clear; D1/M2 not proven` |
| M5 final verdict | `보류 / 환경 문제` |

## 진단

- Calico pod와 Calico CRD가 확인되어 NetworkPolicy-capable CNI 조건 자체는 충족한다.
- `ingress-nginx-controller-admission` Service의 endpoints가 비어 있으므로 현재 상태에서 curl timeout 또는 connection refused는 M2 성공 증거가 아니다.
- controller 로그는 `system:serviceaccount:ingress-nginx:ingress-nginx`가 cluster-scope `services`, `configmaps`, `endpointslices`, `secrets` 등을 list/watch하지 못해 cache sync에 실패하는 흐름을 보인다.
- 이는 NetworkPolicy가 readiness를 막는 상황이라기보다, netpol profile의 M4-style RBAC가 현재 Helm chart/controller scope와 충돌한 상태로 해석한다.
- M4 RBAC 체크 자체는 `kube-system` Secrets가 denied이고 `ingress-nginx` Secrets가 allowed로 확인되어 blast radius 제한 의도와 맞다.
- M3 `block-dangerous-nginx-annotations` ValidatingAdmissionPolicy는 존재한다.

## M2 비교 테스트 상태

M2 직접 Service DNS 비교는 실행하지 않았다. endpoints가 비어 있으면 M2 적용/제거 전후의 curl 결과가 NetworkPolicy 때문인지 controller health 때문인지 분리할 수 없기 때문이다. 이전 attacker pod 실행은 port-forward/local endpoint 가정이 섞여 M2 직접 차단 증거로 사용하지 않는다.

## 권장 다음 조치

- 강제 성공 판정을 하지 않는다.
- Helm uninstall 같은 파괴적 복구는 수행하지 않는다.
- 별도 승인 후, ingress-nginx를 namespace-scoped controller로 재구성하거나 M4 정책을 controller health와 호환되도록 조정한 뒤 endpoints가 생기는지 먼저 검증한다.
- controller가 1/1 Ready이고 admission endpoints가 non-empty가 된 뒤에만 M2 apply/remove/apply 비교를 수행한다.

## 관련 증거 파일

| 파일 | 의미 |
|---|---|
| `calico_evidence.log` | Calico pod/CRD 확인 |
| `controller_health_recheck.log` | controller CrashLoopBackOff 및 endpoint empty 재확인 |
| `controller_logs_tail.log` | RBAC cache-sync failure 증거 |
| `controller_required_rbac_checks.log` | controller 필요 cluster-scope 권한 거부 확인 |
| `m4_can_i_kube_system_with_groups.log` | netpol profile M4 kube-system denied 확인 |
| `m4_can_i_ingress_nginx_with_groups.log` | netpol profile ingress-nginx allowed 확인 |
| `validatingadmissionpolicy.log` | M3 정책 존재 확인 |
| `m2_comparison_skipped.log` | M2 비교 미실행 이유 |
| `safe_recovery_decision.log` | 안전 복구 판단 기록 |
