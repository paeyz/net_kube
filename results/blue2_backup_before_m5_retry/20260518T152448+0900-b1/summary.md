# Blue Team 2 B1 ingress-nginx 패치 검증 요약

- 결과 디렉터리: `results/blue2/20260518T152448+0900-b1`
- Kubernetes context: `cve-2025-1974-lab`
- 비교 기준: 현재 실습 클러스터 이미지 vs `v1.11.5` 패치 이미지

## 핵심 결과

| 항목 | 결과 |
|---|---|
| 패치 전 controller image | `controller=registry.k8s.io/ingress-nginx/controller:v1.11.3@sha256:d56f135b6462cfc476447cfe564b83a45e8bb7da2774963b00d12161112270b7` |
| 패치 후 controller image | `controller=registry.k8s.io/ingress-nginx/controller:v1.11.5@sha256:a1cbad75b0a7098bf9325132794dddf9eef917e8a7fe246749a4cea7ff6f01eb` |
| 패치 전 poc-step3 결과 | `Unknown` |
| 패치 후 poc-step3 차단 여부 | `Unknown` |
| 패치 후 attack-chain T2 도달 여부 | `Reached` |
| 패치 후 attack-chain T3 도달 여부 | `Reached` |

## 해석

- 시작 버전은 고정값으로 가정하지 않았고, 실제 controller image를 기록했다.
- B1의 비교는 `현재 취약 실습 버전`과 `v1.11.5` 사이의 차단 지점 변화다.
- 패치 후에는 auth-snippet 기반 파일 접근이 더 이른 단계에서 막혀야 하며, 그 결과 T2 토큰 추출과 T3 lateral movement가 발생하지 않는 것이 기대된다.
- 탐지 관점에서 패치 전에는 D3/D4가 발생할 수 있다. 패치 후 T1/T2가 차단되면 D3/D4가 발생하지 않는 것이 정상적인 방어 결과다.

## 권장 보고 문장

ingress-nginx controller를 실제 시작 이미지 `controller=registry.k8s.io/ingress-nginx/controller:v1.11.3@sha256:d56f135b6462cfc476447cfe564b83a45e8bb7da2774963b00d12161112270b7`에서 `v1.11.5`로 패치한 뒤, auth-snippet 기반 poc-step3 결과는 `Unknown`로 관찰되었고 attack-chain의 T2/T3 진행은 각각 `Reached`, `Reached`로 제한되었다.

## 관련 로그

| 로그 | 설명 |
|---|---|
| `before_patch_image.txt` | 패치 전 실제 controller image |
| `pre_patch_attack_chain.log` | 패치 전 공격 체인 |
| `pre_patch_poc_step3.log` | 패치 전 auth-snippet 우회 검증 |
| `pre_patch_attack_portforward.log` | 패치 전 attack-chain port-forward 로그 |
| `pre_patch_poc_portforward.log` | 패치 전 poc-step3 port-forward 로그 |
| `helm_upgrade_v1_11_5.log` | v1.11.5 패치 적용 로그 |
| `after_patch_image.txt` | 패치 후 실제 controller image |
| `post_patch_poc_step3.log` | 패치 후 auth-snippet 우회 재검증 |
| `post_patch_attack_chain.log` | 패치 후 공격 체인 |
| `post_patch_poc_portforward.log` | 패치 후 poc-step3 port-forward 로그 |
| `post_patch_attack_portforward.log` | 패치 후 attack-chain port-forward 로그 |
