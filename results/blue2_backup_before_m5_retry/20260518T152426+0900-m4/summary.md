# Blue Team 2 M4 RBAC 최소 권한화 검증 요약

- 결과 디렉터리: `results/blue2/20260518T152426+0900-m4`
- Kubernetes context: `cve-2025-1974-lab`
- ServiceAccount: `system:serviceaccount:ingress-nginx:ingress-nginx`
- 광범위 ClusterRoleBinding 잔존 개수: `1`
- 광범위 ClusterRoleBinding 제거 옵션 사용: `false`

## 핵심 결과

| 항목 | 결과 |
|---|---|
| M4 적용 전 kube-system Secrets list 권한 | `yes` |
| M4 적용 후 kube-system Secrets list 권한 | `yes` |
| M4 적용 전 ingress-nginx Secrets list 권한 | `yes` |
| M4 적용 후 ingress-nginx Secrets list 권한 | `yes` |
| 탈취 토큰으로 kube-system Secrets 접근 | `Allowed` |
| 탈취 토큰으로 ingress-nginx Secrets 접근 | `Allowed` |
| M4 이후 T2 토큰 접근 관찰 | `Observed` |
| M4 이후 T3 lateral movement 제한 | `Unknown` |

## 해석

- M4는 CVE-2025-1974 자체의 토큰 파일 접근(T2)을 반드시 막는 방어가 아니다.
- M4의 성공 기준은 탈취된 ingress-nginx ServiceAccount 토큰으로 `kube-system` Secrets 접근이 `Forbidden` 또는 `no`가 되는 것이다.
- `ingress-nginx` 네임스페이스 권한은 TLS Secret 등 운영 필요성 때문에 남아 있을 수 있으며, 이는 blast radius가 네임스페이스 안으로 제한되었는지 확인하는 지표다.
- D3는 토큰 파일 접근을 계속 탐지할 수 있다. D4는 Kubernetes API 접근 시도를 보여주되, M4 이후에는 `Forbidden` 결과가 기대된다.

## 권장 보고 문장

M4 RBAC 최소 권한화 적용 후 ingress-nginx ServiceAccount의 kube-system Secrets 접근은 `yes`로 제한되었으며, 토큰 탈취 가능성은 남더라도 탈취 토큰의 lateral movement blast radius가 축소되었다.

## 관련 로그

| 로그 | 설명 |
|---|---|
| `baseline_attack_chain.log` | M0 취약 baseline 공격 체인 |
| `baseline_portforward.log` | baseline port-forward 로그 |
| `rbac_before_kube_system.log` | M4 전 kube-system RBAC 확인 |
| `rbac_after_kube_system.log` | M4 후 kube-system RBAC 확인 |
| `token_test_kube_system.log` | 탈취 토큰 기반 kube-system Secrets 접근 결과 |
| `post_m4_attack_chain.log` | M4 이후 공격 체인 재검증 |
| `post_m4_portforward.log` | M4 이후 port-forward 로그 |
| `broad_clusterrolebindings_after_m4.tsv` | M4 후 남아 있는 광범위 CRB |
