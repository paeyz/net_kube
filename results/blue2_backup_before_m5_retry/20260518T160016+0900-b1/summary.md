# Blue Team 2 B1 ingress-nginx 패치 검증 요약

- 결과 디렉터리: `results/blue2/20260518T160016+0900-b1`
- Kubernetes context: `cve-2025-1974-lab`
- 비교 기준: vulnerable chart `4.11.3` / controller `v1.11.3` vs patched chart `4.11.5` / controller `v1.11.5`
- B1 exploit-specific patch validation: `passed`
- End-to-end attack-chain validation: `inconclusive due to kubectl_exec fallback reachability`
- 판정 이유: v1.11.5 blocked CVE file enumeration from 8/12 to 0/12

## 핵심 결과

| 항목 | 결과 |
|---|---|
| vulnerable baseline controller image | `controller=registry.k8s.io/ingress-nginx/controller:v1.11.3@sha256:d56f135b6462cfc476447cfe564b83a45e8bb7da2774963b00d12161112270b7` |
| vulnerable baseline image verified | `true` |
| reset Helm exit status | `0` |
| patched controller image | `controller=registry.k8s.io/ingress-nginx/controller:v1.11.5@sha256:a1cbad75b0a7098bf9325132794dddf9eef917e8a7fe246749a4cea7ff6f01eb` |
| patched image verified | `true` |
| Helm upgrade exit status | `0` |
| Helm release status after patch | `deployed` |
| Helm upgrade succeeded | `true` |
| pre_patch_file_enum_count | `8` |
| post_patch_file_enum_count | `0` |
| exploit_path_blocked | `true` |
| fallback_t2_t3_observed | `true` |
| poc_step3_status | `pre=Reached; post=Allowed without direct leak` |
| b1_exploit_path_verdict | `passed` |
| b1_end_to_end_verdict | `inconclusive due to kubectl_exec fallback reachability` |
| pre-patch poc-step3 결과 | `Reached` |
| pre-patch attack-chain T1 | `Reached` |
| pre-patch attack-chain T2 | `Reached via kubectl_exec fallback` |
| pre-patch attack-chain T3 | `Reached` |
| post-patch poc-step3 차단 여부 | `Allowed without direct leak` |
| post-patch attack-chain T1 | `Blocked or no files reached` |
| post-patch attack-chain T2 | `Reached via kubectl_exec fallback` |
| post-patch attack-chain T3 | `Reached` |
| post-patch exploit path blocked before T2/T3 | `true` |

## 해석

- B1은 먼저 취약 baseline(`4.11.3` / `v1.11.3`)으로 되돌린 뒤 pre-patch 공격 결과를 기록한다.
- 패치 단계는 `4.11.5` / `v1.11.5`로 업그레이드하고, Helm release가 `deployed`인지와 controller image가 `v1.11.5`인지 모두 확인한다.
- ConfigMap field-manager 충돌을 줄이기 위해 Helm upgrade에 server-side apply와 `--force-conflicts`를 사용한다. 충돌 또는 upgrade 실패가 발생하면 repair upgrade를 별도 로그에 남기고, 실패를 조용히 무시하지 않는다.
- B1 exploit-specific patch validation은 CVE-2025-1974의 파일 열거 경로가 패치 후 차단되었는지를 본다.
- `kubectl_exec` fallback은 실습 편의용 경로이며 CVE exploit path와 동일하지 않다. 따라서 fallback으로 T2/T3가 관찰되어도 exploit-specific patch validation 실패로 계산하지 않는다.
- `v1.11.5`는 파일 열거를 `8/12`에서 `0/12`로 낮췄다.
- direct `poc-step3`는 port-forward readiness가 정상화되어 실행되었고, pre-patch에서는 파일 접근이 직접 관찰되었으며 post-patch에서는 응답 내 직접 파일 누출이 관찰되지 않았다.
- 전체 end-to-end attack-chain은 fallback 및 port-forward readiness 영향이 있으면 inconclusive로 보고, exploit-specific patch validation과 분리해 보고한다.

## 권장 보고 문장

B1 검증은 vulnerable baseline `controller=registry.k8s.io/ingress-nginx/controller:v1.11.3@sha256:d56f135b6462cfc476447cfe564b83a45e8bb7da2774963b00d12161112270b7`에서 patched image `controller=registry.k8s.io/ingress-nginx/controller:v1.11.5@sha256:a1cbad75b0a7098bf9325132794dddf9eef917e8a7fe246749a4cea7ff6f01eb`로 전환한 뒤 수행했다. B1 exploit-specific patch validation은 `passed`이고, end-to-end attack-chain validation은 `inconclusive due to kubectl_exec fallback reachability`이다. 근거: v1.11.5 blocked CVE file enumeration from 8/12 to 0/12.

## 관련 로그

| 로그 | 설명 |
|---|---|
| `reset_vulnerable_baseline.log` | 취약 baseline Helm reset |
| `reset_vulnerable_rollout.log` | 취약 baseline rollout |
| `vulnerable_baseline_image.txt` | 취약 baseline 실제 image |
| `vulnerable_baseline_helm_release.txt` | 취약 baseline Helm release |
| `allow_snippet_patch.log` | allow-snippet-annotations=true 보정 |
| `pre_patch_attack_chain.log` | 패치 전 공격 체인 |
| `pre_patch_poc_step3.log` | 패치 전 auth-snippet 우회 검증 |
| `helm_upgrade_v1_11_5.log` | v1.11.5 패치 적용 로그 |
| `helm_upgrade_v1_11_5_repair.log` | 충돌 시 repair upgrade 로그 |
| `after_patch_image.txt` | 패치 후 실제 controller image |
| `after_patch_helm_release.txt` | 패치 후 Helm release 상태 |
| `post_patch_poc_step3.log` | 패치 후 auth-snippet 우회 재검증 |
| `post_patch_attack_chain.log` | 패치 후 공격 체인 |
