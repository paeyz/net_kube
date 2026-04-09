# Red Team Proposal — CVE-2025-1974 공격 실험

> 작성자: Red Team (1인)
> 대상 환경: 로컬 Minikube 격리 클러스터 (cve-2025-1974-lab)
> 목적: 공격 체인 완전 자동화 + Blue/Detection 팀의 방어·탐지 실험 대상 제공

---

## 1. 현재 달성 수준

```
✅ Step 1  webhook 비인증 접근 확인
✅ Step 2  configuration-snippet → 차단 확인 (기준선)
✅ Step 3  auth-snippet → allow-snippet-annotations 우회
✅ Step 4  SA 토큰 탈취 + Kubernetes API 접근 (kube-system secrets list)
```

PoC는 완성됐다. 이제 "단발성 재현"을 "재현 가능한 공격 체인"으로 확장한다.

---

## 2. 공격 목표

### 최종 목표 (End Goal)

```
클러스터 내 임의 파드
  → admission webhook 비인증 접근
  → auth-snippet으로 컨트롤러 파드 파일 읽기
  → SA 토큰 탈취
  → Kubernetes API Lateral Movement
  → 클러스터 전체 권한 탈취 (cluster-admin 수준)
```

### 단계별 세부 목표

| 단계 | 목표 | 성공 지표 |
|------|------|-----------|
| T1 | 파일 열거 자동화 | 10개 이상 경로 접근 가능 여부 확인 |
| T2 | SA 토큰 완전 추출 | JWT 전체 문자열 획득 |
| T3 | API Lateral Movement | kube-system secrets 내용 열람 |
| T4 | 권한 상승 | 다른 SA 토큰 → 더 높은 권한 획득 |
| T5 | 공격 자동화 | `make attack-chain` 한 번에 T1→T4 실행 |

---

## 3. 공격 시나리오 설계

### 시나리오 A — 파일 열거 (File Enumeration)

**원리**: `auth-snippet: include <경로>;` 로 임의 경로에 nginx가 접근 시도

```
대상 파일 목록 (우선순위 순):
  /var/run/secrets/kubernetes.io/serviceaccount/token      ← SA 토큰 (완료)
  /var/run/secrets/kubernetes.io/serviceaccount/namespace  ← 네임스페이스
  /var/run/secrets/kubernetes.io/serviceaccount/ca.crt     ← 클러스터 CA
  /etc/hosts                                               ← 내부 DNS 정보
  /proc/self/environ                                       ← 환경변수 (비밀값)
  /proc/self/cmdline                                       ← 프로세스 실행 인자
  /etc/resolv.conf                                         ← DNS 서버
  /etc/passwd                                              ← 사용자 정보
  /proc/net/tcp                                            ← 열린 포트 목록
  /sys/class/net/eth0/address                              ← MAC 주소
```

**성공 기준**: 각 경로에 대해 "접근 가능(에러에 경로 포함)" / "접근 불가(파일 없음)" 분류

---

### 시나리오 B — SA 토큰 완전 추출

**문제**: 현재 `include /token;` 은 경로만 노출하고 내용을 직접 노출하지 않음

**접근 방법 3가지**:

```
방법 1: kubectl exec (직접 읽기) — 현재 사용 중
  kubectl exec -n ingress-nginx <pod> -- cat /token

방법 2: nginx error_log 조작
  error_log /proc/self/fd/1 debug;
  include /token;
  → debug 레벨에서 토큰 내용이 응답에 포함될 가능성

방법 3: nginx map + include 조합
  → 파일 내용을 변수로 읽는 nginx 지시어 실험
```

**검증 방법**: 추출한 JWT를 base64 디코딩해서 `sub`, `iss`, `exp` 클레임 확인

---

### 시나리오 C — Kubernetes API Lateral Movement

탈취한 SA 토큰으로 클러스터 내에서 할 수 있는 것:

```
Level 1 — 정보 수집
  kubectl --token get secrets -A          ← 완료
  kubectl --token get configmaps -A       ← 환경 설정 정보
  kubectl --token get pods -A             ← 실행 중인 파드 목록
  kubectl --token get serviceaccounts -A  ← 다른 SA 목록

Level 2 — 다른 SA 토큰 탈취
  secrets 목록에서 다른 SA 토큰을 찾아 디코딩
  → kube-system SA 토큰이 있다면 cluster-admin 수준 가능

Level 3 — 권한 상승 시도
  kubectl --token auth can-i create pods -n kube-system
  → 파드 생성 가능 시: hostPath 마운트로 노드 파일시스템 접근
```

---

### 시나리오 D — 공격 자동화 (Attack Chain)

위 A→B→C를 단일 스크립트로 연결:

```
attack_chain.py 실행 흐름:

  [0] 사전 확인
      - port-forward 연결 확인
      - 클러스터 상태 확인

  [1] 파일 열거 (시나리오 A)
      - 10개 경로 순회
      - 접근 가능 경로 목록 출력

  [2] SA 토큰 추출 (시나리오 B)
      - kubectl exec으로 JWT 완전 획득
      - JWT 헤더/페이로드 디코딩

  [3] API Lateral Movement (시나리오 C)
      - Level 1: 정보 수집 자동화
      - Level 2: 다른 SA 토큰 탈취 시도
      - Level 3: 권한 상승 시도

  [4] 결과 리포트 생성
      - attack_result_<timestamp>.json
      - 공격 성공/실패 항목 요약
```

---

## 4. 코드 구조

```
poc/
  cve_2025_1974_poc.py      # 기존: Step 1~3
  comparison.py             # 기존: A/B 비교 + Stage 4
  attack_chain.py           # 신규: 전체 자동화 체인  ← 핵심 작업
  modules/
    file_enum.py            # 신규: 파일 열거 모듈
    token_extract.py        # 신규: 토큰 추출 + JWT 파싱
    lateral_move.py         # 신규: API Lateral Movement
    reporter.py             # 신규: 결과 리포트 생성
results/
  .gitkeep                  # 실행 결과 저장 (gitignore)
```

### attack_chain.py 핵심 인터페이스

```python
# 사용법
python3 poc/attack_chain.py [--target https://127.0.0.1:8443] [--out results/]

# 또는
make attack-chain
```

---

## 5. 실험 환경 세팅

### 5-1. 기본 환경 (현재 완료)

```bash
make cluster-up          # Minikube + ingress-nginx v1.11.4
make cluster-status      # 상태 확인
```

### 5-2. 실험 전 초기화 절차

```bash
# ConfigMap을 기본값으로 유지 (allow=false)
kubectl get cm ingress-nginx-controller -n ingress-nginx \
  -o jsonpath='{.data.allow-snippet-annotations}'
# 출력: false (또는 빈값) → 정상

# 이전 실험 결과 삭제
rm -f results/attack_result_*.json
```

### 5-3. port-forward 관리

```bash
# 실험 전 (백그라운드로 유지)
kubectl port-forward svc/ingress-nginx-controller-admission \
  8443:443 -n ingress-nginx &

# 실험 후 정리 (attack_chain.py가 자동 처리)
```

### 5-4. 실험 반복 시 주의사항

| 항목 | 이유 | 처리 방법 |
|------|------|-----------|
| SA 토큰 만료 | Kubernetes v1.30은 time-bound JWT 사용 | 매 실험 전 토큰 재추출 |
| port-forward 끊김 | WSL2 재시작 시 | `make cluster-up` 후 재연결 |
| ConfigMap 값 변경 | Blue Team이 false로 복원했을 수 있음 | 실험 전 반드시 확인 |

---

## 6. 실험 방법론

### 6-1. 실험 단위

각 시나리오를 **독립적으로 실행**할 수 있도록 설계한다.

```bash
make attack-enum      # 시나리오 A: 파일 열거만 실행
make attack-token     # 시나리오 B: 토큰 추출만 실행
make attack-lateral   # 시나리오 C: Lateral Movement만 실행
make attack-chain     # 전체 체인 실행
```

### 6-2. 결과 기록 방식

```json
{
  "timestamp": "2026-04-09T15:30:00",
  "target": "https://127.0.0.1:8443",
  "scenario_a": {
    "accessible_files": [
      "/var/run/secrets/kubernetes.io/serviceaccount/token",
      "/etc/hosts",
      "/proc/self/environ"
    ],
    "inaccessible_files": ["/etc/shadow"]
  },
  "scenario_b": {
    "token_extracted": true,
    "jwt_header": {"alg": "RS256", "kid": "..."},
    "sa_name": "ingress-nginx",
    "namespace": "ingress-nginx"
  },
  "scenario_c": {
    "level1_success": true,
    "secrets_count": 12,
    "level2_tokens_found": ["other-sa-token"],
    "level3_can_create_pods": false
  }
}
```

### 6-3. Blue/Detection 팀과의 협력 프로토콜

```
실험 전  → Detection 팀에 "공격 시작" 알림 (시각 기록)
실험 중  → 조용히 실행 (Detection 팀이 탐지할 수 있도록)
실험 후  → Blue 팀이 방어 정책 적용 → Red 팀이 우회 재시도
최종     → 양 팀 결과 비교해서 timeline.md 작성
```

---

## 7. 개발 일정

| 주차 | 작업 | 산출물 |
|------|------|--------|
| 1주차 | file_enum.py + token_extract.py 구현 및 실험 | 접근 가능 파일 목록, 토큰 추출 결과 |
| 2주차 | lateral_move.py 구현 + Level 1~3 실험 | API 접근 범위 확인 |
| 3주차 | attack_chain.py 통합 + reporter.py | 자동화 완성, 리포트 샘플 |
| 4주차 | Blue/Detection 팀과 통합 시나리오 실행 | timeline.md, attack_report.md |

---

## 8. 최종 산출물

```
poc/attack_chain.py           # 전체 공격 자동화 스크립트
poc/modules/file_enum.py      # 파일 열거 모듈
poc/modules/token_extract.py  # 토큰 추출 + JWT 파싱
poc/modules/lateral_move.py   # Kubernetes API Lateral Movement
poc/modules/reporter.py       # JSON/Markdown 결과 리포트
results/attack_result_*.json  # 실험별 결과 (gitignore)
docs/attack_report.md         # 공격 흐름 + 증거 포함 최종 보고서
```

---

## 9. 윤리 및 제약

- 모든 실험은 로컬 Minikube 격리 환경에서만 수행
- 외부 시스템 접근 없음 (`127.0.0.1` 루프백만 사용)
- RCE(`load_module`) 실제 실행 없음 — 경로 문서화만 수행
- 실험 결과 파일은 `.gitignore` 처리 (SA 토큰 등 민감정보 포함 가능)
- `results/` 디렉터리는 `.gitkeep`만 커밋
