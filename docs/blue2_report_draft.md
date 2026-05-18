# Blue Team 2 보고서 초안

> 이 문서는 `results/blue2/*/summary.md`의 최신 요약만 사용해 생성했다. 원시 토큰, Secret 값, Authorization 헤더는 포함하지 않는다.

## 1. Blue Team 2 역할

Blue Team 2는 CVE-2025-1974 ingress-nginx 실습에서 M4 RBAC 최소 권한화, B1 패치 검증, M5 통합 검증을 담당한다. 목표는 취약점 재현 여부를 과장하지 않고, 각 방어가 어느 공격 단계를 막거나 제한하는지 재현 가능한 로그로 설명하는 것이다.

## 2. 실험 환경

| 항목 | 내용 |
|---|---|
| 실행 범위 | 로컬 Minikube 실습 환경 전용 |
| 외부 대상 | 사용하지 않음 |
| M4 최신 요약 | `results/blue2/20260518T153339+0900-m4/summary.md` |
| B1 최신 요약 | `results/blue2/20260518T160016+0900-b1/summary.md` |
| M5 최신 요약 | 미실행 |
| M0 vulnerable baseline | M4 baseline_attack_chain.log에 기록됨 |

## 3. M4 RBAC 최소 권한화

| 항목 | 결과 |
|---|---|
| M4 적용 전 kube-system Secrets 조회 권한 | 허용 |
| M4 적용 후 kube-system Secrets 조회 권한 | 거부 |
| 격리 토큰 기반 kube-system Secrets 권한 | 거부 |
| M4 적용 전 ingress-nginx Secrets 조회 권한 | 허용 |
| M4 적용 후 ingress-nginx Secrets 조회 권한 | 허용 |
| 격리 토큰 기반 ingress-nginx Secrets 권한 | 허용 |
| 광범위 ClusterRoleBinding 제거 옵션 | 예 |
| 광범위 ClusterRoleBinding 잔존 수 | 1 -> 0 |
| 토큰 파일 접근 관찰 | 관찰됨 |
| T3 lateral movement 제한 | 예 |

**현재 판정:** `성공`

광범위 ClusterRoleBinding 제거 후 잔존 수가 0으로 확인되었고, 격리 토큰 테스트에서 kube-system Secrets 접근이 거부되었다.

M4의 핵심 성공 기준은 ingress-nginx ServiceAccount가 `kube-system` Secrets를 더 이상 조회하지 못하는 것이다. 이번 결과에서는 광범위 ClusterRoleBinding 제거와 격리된 토큰 테스트가 함께 확인되어 kube-system Secrets 접근 거부를 증명했다.
`ingress-nginx` 네임스페이스 접근은 운영에 필요한 TLS Secret 등 때문에 허용되거나 제한된 범위로 남을 수 있으며, 이는 기대 가능한 결과다. M4는 토큰 파일 접근 자체를 막는 통제가 아니라, 토큰이 노출된 뒤 피해 범위를 줄이는 RBAC 최소 권한화 통제다.

## 4. B1 패치 검증

| 항목 | 결과 |
|---|---|
| 취약 기준 controller 이미지 | `registry.k8s.io/ingress-nginx/controller:v1.11.3` |
| 패치 controller 이미지 | `registry.k8s.io/ingress-nginx/controller:v1.11.5` |
| 패치 후 Helm release 상태 | `deployed` |
| 패치 전 T1 파일 열거 수 | `8` |
| 패치 후 T1 파일 열거 수 | `0` |
| CVE 공격 경로 차단 여부 | 예 |
| CVE 공격 경로 패치 검증 | 통과 |
| 전체 end-to-end 공격 체인 검증 | 불확실, 실패로 판정하지 않음 |
| kubectl_exec 대체 경로 T2/T3 관찰 | 예 |
| poc-step3 상태 | 패치 전 도달, 패치 후 응답 내 직접 누출 없음 |

**현재 판정:** `CVE 공격 경로 검증 통과 / 전체 공격 체인 검증 불확실`

패치 후 Helm release는 deployed이고, v1.11.5에서 T1 파일 열거가 8에서 0으로 감소했다. kubectl_exec 대체 경로는 실습 편의 기능이므로 CVE-2025-1974 공격 성공과 동일하게 보지 않는다.

B1은 취약 기준인 `registry.k8s.io/ingress-nginx/controller:v1.11.3`과 패치 버전인 `registry.k8s.io/ingress-nginx/controller:v1.11.5`를 비교했다. 패치 전 T1 파일 열거는 8건이었고, 패치 후에는 0건이었다.
따라서 CVE-2025-1974 공격 경로에 한정한 패치 검증은 통과로 본다. 다만 `kubectl_exec` 대체 경로로 T2/T3가 관찰된 것은 실습 편의용 도달성 확인이며 CVE-2025-1974 취약점 성공과 동일하지 않다. 그래서 전체 end-to-end 공격 체인 검증은 실패가 아니라 불확실로 표시한다.

## 5. M5 Full Stack 통합 검증

| 항목 | 결과 |
|---|---|
| 실행 상태 | 아직 summary.md 없음 |

M5는 M2, M3, M4가 중복 방어가 아니라 서로 다른 경로를 담당하는 defense-in-depth 조합임을 확인한다. M2는 네트워크 직접 접근, M3는 kube-apiserver 경유 악성 Ingress, M4는 탈취 토큰의 권한 범위를 다룬다.

## 6. Red Team 공격 단계와의 연결

| 공격 단계 | 의미 | 관련 방어 | 최신 관찰 요약 |
|---|---|---|---|
| M0/T1 | webhook 접근 및 파일 열거 | B1, M2, M3 | M4 baseline_attack_chain.log에 기록됨 |
| T2 | ingress-nginx SA 토큰 접근 | B1, M2 | 관찰됨 |
| T3 | 탈취 토큰으로 Kubernetes API 접근 | M4 | 예 |
| T4 | 결과 리포트 생성 | 로그 위생/.gitignore | `results/blue2/`에 민감정보 제거 요약 보관 |

## 7. Detection Team D3/D4와의 연결

| 탐지 | 연결 지점 | 해석 |
|---|---|---|
| D3 | 토큰 파일 접근 | M4만으로는 계속 발생할 수 있다. B1 또는 M2가 더 앞에서 막으면 미발생이 정상일 수 있다. |
| D4 | 탈취 토큰 API 접근 | M4 이후에는 API 접근 시도는 보이더라도 `Forbidden` 결과가 기대된다. |
| D1/D2 참고 | webhook 직접 접근, 위험 annotation | M5에서 M2/M3와 함께 해석하면 어느 지점에서 공격이 멈췄는지 설명하기 쉽다. |

## 8. 운영 환경 권장 조합

| 우선순위 | 권장 조치 | 이유 |
|---|---|---|
| 1 | ingress-nginx 패치 적용 | 취약한 CVE 공격 경로를 가장 앞단에서 제거 |
| 2 | NetworkPolicy 적용 및 CNI 검증 | webhook 직접 노출면 축소 |
| 3 | 위험 annotation 차단 Admission 정책 적용 | kube-apiserver 경유 악성 Ingress 제한 |
| 4 | ingress-nginx RBAC 최소 권한화 | 토큰 탈취 이후 kube-system 등으로 확산되는 blast radius 축소 |
| 5 | D3/D4 탐지 유지 | 토큰 파일 접근과 탈취 토큰 API 접근 시도를 관찰 가능하게 함 |

## 9. 한계 및 주의사항

- 이 보고서는 원시 로그를 다시 실행하지 않고 최신 `summary.md`만 합성한다.
- `미실행`, `Unknown`, `미확인`은 실험 성공으로 해석하면 안 된다.
- B1의 `kubectl_exec` 대체 경로는 실습 편의용 경로이며 CVE-2025-1974 공격 경로 자체가 아니다.
- M5 검증은 Calico, Cilium, Antrea 같은 NetworkPolicy 집행 가능 CNI와 Docker attacker pod 검증이 있어야 완전해진다.
- D3는 M4 이후에도 발생할 수 있다. M4는 토큰 파일 접근을 막는 통제가 아니라 탈취 토큰의 권한 범위를 줄이는 통제다.
- 원시 audit/Falco 로그, 토큰 dump, Secret dump, attack_result 파일은 커밋하지 않는다.
