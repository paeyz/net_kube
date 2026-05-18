# Blue Team 2 실행 Runbook

## 1. Blue Team 2 책임 범위

Blue Team 2는 CVE-2025-1974 ingress-nginx 실습에서 다음 세 가지를 검증한다.

| 구분 | 책임 |
|---|---|
| M4 | ingress-nginx ServiceAccount의 RBAC를 최소 권한으로 제한 |
| B1 | 현재 실습 버전과 v1.11.5 패치 버전의 차단 효과 비교 |
| M5 | M2 NetworkPolicy, M3 ValidatingAdmissionPolicy, M4 RBAC 통합 검증 |

이 자동화는 교육용 로컬 실습 전용이다. 외부 IP, 외부 Kubernetes 클러스터, 운영 환경을 대상으로 실행하면 안 된다.

## 2. Red Team 필요 여부

Red Team 담당자가 같은 시간에 직접 조작할 필요는 없다. Blue Team 2 스크립트가 기존 `make attack-chain`, `make poc-step3`, attacker pod 관련 target을 호출해 방어 전후를 재현한다.

다만 발표나 최종 보고서에서는 Red Team과 다음 항목을 맞춰야 한다.

| 확인 항목 | 이유 |
|---|---|
| 공격 단계 이름 T1/T2/T3/T4 | 방어가 어느 단계에서 작동했는지 같은 용어로 설명 |
| `attack-chain` 결과 해석 | 토큰 추출 성공/실패와 lateral movement 결과를 동일하게 해석 |
| D2 trigger 사용 여부 | Detection Team의 Gatekeeper/Audit Log 확인과 연결 |

## 3. Docker 필요 여부

M4와 B1 검증은 Docker가 없어도 실행할 수 있다. M5에서 M2 NetworkPolicy를 제대로 증명하려면 in-cluster attacker pod 검증이 중요하므로 Docker가 필요하다.

| Docker 상태 | M5 해석 |
|---|---|
| Docker 사용 가능 | `make docker-build`, `make attacker-deploy`, `make attacker-logs`, `make attacker-delete`까지 실행 |
| Docker 없음 또는 daemon 중지 | port-forward 검증만 수행. M2의 in-cluster 직접 접근 차단은 완전 입증 불가 |

## 4. 실행 전 안전 규칙

- 현재 `kubectl` context가 로컬 Minikube 실습 context인지 확인한다.
- 원시 ServiceAccount token, JWT, Bearer token, Authorization header, Kubernetes Secret 값을 출력하거나 공유하지 않는다.
- 모든 결과는 `results/blue2/` 아래에 저장한다.
- `results/blue2/`, 원시 audit/Falco 로그, token dump, secret dump, `attack_result_*.json` 파일은 커밋하지 않는다.
- 클러스터를 변경하는 작업은 스크립트가 먼저 내용을 출력하고 `yes` 확인을 요구한다. 자동 실행이 필요할 때만 스크립트에 `--yes`를 직접 붙인다.

## 5. 권장 실행 순서

```bash
make blue2-m4
make blue2-b1
make blue2-m5
make blue2-report
```

각 target은 다음 스크립트를 호출한다.

| Target | 동작 |
|---|---|
| `make blue2-m4` | `scripts/blue2/m4_rbac_validation.sh` |
| `make blue2-m4-remove-broad-crb` | broad ClusterRoleBinding 백업 후 삭제 옵션 포함 |
| `make blue2-b1` | `scripts/blue2/b1_patch_validation.sh` |
| `make blue2-m5` | `scripts/blue2/m5_fullstack_validation.sh` |
| `make blue2-report` | `docs/blue2_report_draft.md` 생성 |
| `make blue2-clean` | 확인 후 `results/blue2/`만 삭제 |

## 6. M4 해석

M4는 RBAC 최소 권한화다. 중요한 점은 M4가 토큰 파일 접근 자체를 반드시 막는 방어가 아니라는 것이다.

| 관찰 | 해석 |
|---|---|
| T2 토큰 접근이 계속 관찰됨 | M4 단독으로는 가능하다. 실패가 아니다. |
| `kube-system` Secrets 접근이 `Forbidden` 또는 `no` | M4 성공 기준 |
| `ingress-nginx` namespace Secrets 접근이 남아 있음 | TLS Secret 등 필요 권한일 수 있다. blast radius가 namespace로 제한되었는지 확인 |
| broad ClusterRoleBinding 잔존 | M4 효과를 무력화할 수 있으므로 경고를 확인 |

보고서에는 다음 문장을 기준으로 작성한다.

> M4 적용 후 토큰 접근 가능성은 남아 있을 수 있으나, 탈취 토큰의 `kube-system` Secrets 접근이 Forbidden으로 제한되어 lateral movement blast radius가 축소되었다.

## 7. B1 해석

B1은 시작 버전을 `v1.11.4`로 가정하지 않는다. 스크립트는 실제 현재 controller image를 기록한 뒤 `v1.11.5` 패치와 비교한다.

| 관찰 | 해석 |
|---|---|
| 패치 전 `poc-step3`가 auth-snippet 파일 접근을 보임 | 현재 실습 버전에서 취약 경로 재현 |
| 패치 후 `poc-step3`가 차단됨 | 패치가 더 이른 단계에서 T2/T3를 막음 |
| 패치 후 D3/D4가 발생하지 않음 | T1/T2가 막혔다면 정상적인 기대 결과 |

## 8. M5 해석

M5는 M2, M3, M4가 같은 방어를 반복하는지 확인하는 것이 아니라 서로 다른 공격 경로를 나눠 막는지 확인한다.

| 방어 | 담당 경로 |
|---|---|
| M2 NetworkPolicy | 클러스터 내부 attacker pod의 webhook 직접 접근 제한 |
| M3 ValidatingAdmissionPolicy | kube-apiserver 경유 위험 annotation 차단 |
| M4 RBAC | 토큰 탈취 이후 Kubernetes API lateral movement 제한 |

주의할 점은 port-forward 경로다. port-forward는 kube-apiserver를 통과하므로 M2의 in-cluster 직접 네트워크 차단과 다르다. M2를 강하게 입증하려면 Docker attacker pod 검증 로그가 필요하다.

## 9. Detection Team 협업

Detection Team과는 다음 로그를 맞춰 보면 된다.

| 탐지 | Blue Team 2 연결 |
|---|---|
| D1 webhook direct access | M5 attacker pod validation |
| D2 dangerous auth-snippet annotation | M3 적용 후 VAP/Gatekeeper/Audit 결과 |
| D3 token file access | M4 또는 B1 전후 T2 결과 |
| D4 Kubernetes API access with stolen token | M4 전후 `Forbidden` 여부 |

M2나 B1이 초기에 공격을 막으면 D3/D4가 발생하지 않을 수 있다. 이는 탐지 실패가 아니라 방어가 더 앞 단계에서 작동한 결과일 수 있다.

## 10. 캡처할 스크린샷/로그

| 항목 | 파일 |
|---|---|
| M4 요약 | `results/blue2/<timestamp>-m4/summary.md` |
| M4 kube-system 권한 | `rbac_before_kube_system.log`, `rbac_after_kube_system.log`, `token_test_kube_system.log` |
| B1 이미지 비교 | `before_patch_image.txt`, `after_patch_image.txt` |
| B1 패치 전후 PoC | `pre_patch_poc_step3.log`, `post_patch_poc_step3.log` |
| M5 통합 결과 | `results/blue2/<timestamp>-m5/summary.md` |
| M5 attacker pod | `attacker_logs.log` 또는 `attacker_pod_validation_skipped.txt` |
| 최종 보고서 초안 | `docs/blue2_report_draft.md` |

발표 자료에는 원시 토큰이나 Secret 값이 보이지 않는 sanitized 로그와 요약만 사용한다.
