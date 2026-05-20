# Blue Team 2 M5 Full Stack 통합 검증 요약

- 결과 디렉터리: `results/blue2/20260518T213554+0900-m5`
- Kubernetes context: `cve-2025-1974-netpol`
- 적용 조합: M2 NetworkPolicy + M3 ValidatingAdmissionPolicy + M4 RBAC
- NetworkPolicy CNI 확인: `candidate-found`

## 핵심 결과

| 항목 | 결과 |
|---|---|
| M2 NetworkPolicy 적용/집행 | `Ran` |
| M3 ValidatingAdmissionPolicy | `Policy present` |
| M4 RBAC kube-system Secrets 제한 | `kube-system Secrets list denied` |
| Docker attacker pod 검증 실행 | `ran` |
| attacker pod 검증 결과 | `failed-or-unknown` |
| port-forward attack-chain 결과 | `blocked-or-forbidden` |

## 해석

- M2는 클러스터 내부 공격자 파드가 webhook에 직접 접근하는 경로를 제한하는 방어다. NetworkPolicy-capable CNI가 없으면 정책 객체는 존재해도 실제 차단이 보장되지 않는다.
- M3는 kube-apiserver 경유 Ingress 생성/수정에서 위험한 `auth-snippet` 또는 `server-snippet`을 차단한다.
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
| `networkpolicy_cni_check.txt` | NetworkPolicy 집행 가능 CNI 후보 확인 |
| `apply_m2.log` | M2 적용 |
| `apply_m3.log` | M3 적용 |
| `apply_m4.log` | M4 적용 |
| `m4_can_i_kube_system.log` | M4 kube-system Secrets 권한 확인 |
| `port_forward_attack_chain.log` | port-forward 기반 공격 체인 |
| `m5_portforward.log` | M5 port-forward 로그 |
| `attacker_logs.log` | Docker 사용 가능 시 in-cluster attacker pod 결과 |
