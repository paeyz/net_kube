# CVE-2025-1974 (IngressNightmare) Local Lab

CVE-2025-1974 취약점의 동작 원리를 로컬 격리 환경에서 단계별로 재현하는 학습 저장소.

## Safety

- 로컬 단일 머신 (Minikube)에서만 실행
- 외부 노출 없음 — 모든 통신은 `127.0.0.1` 루프백
- 실제 exploit 코드 / 무기화 / 외부 대상 공격 없음
- 민감정보·자격증명은 저장소에 포함하지 않음

---

## 취약점 개요

**CVE-2025-1974 (IngressNightmare)**은 ingress-nginx admission webhook에서 발생하는 취약점이다.

- **영향 버전**: ingress-nginx < 1.11.5, < 1.12.1
- **CVSS**: 9.8 (Critical)
- **공격 전제**: 클러스터 내 임의 파드에서 admission webhook 서비스에 접근 가능

**공격 체인**:
1. admission webhook은 인증 없이 AdmissionReview 요청을 처리한다
2. `auth-snippet` 어노테이션이 `allow-snippet-annotations=false` 검사를 우회한다
3. 주입된 nginx `include` 지시어가 `nginx -t` 검증 중 실행된다
4. 컨트롤러 파드의 ServiceAccount 토큰으로 Kubernetes API 접근이 가능하다

---

## 진행 상태

| 단계 | 내용 | 상태 |
|------|------|------|
| Stage 1 | Python mock 시뮬레이션 (admission 흐름 학습) | ✅ 완료 |
| Stage 2 | Minikube + ingress-nginx v1.11.4 클러스터 구축 | ✅ 완료 |
| Stage 3 | webhook 비인증 접근 + auth-snippet 우회 재현 | ✅ 완료 |
| Stage 4 | SA 토큰 확인 + Kubernetes API 접근 체인 | ✅ 완료 |
| Stage 5 | Red Team 공격 체인 자동화 + Docker 인수인계 | ✅ 완료 |

### Stage 3 달성 수준

```
✅ webhook 인증 없이 AdmissionReview 요청 처리됨
✅ configuration-snippet → allow-snippet-annotations=false 차단 확인
✅ auth-snippet → allow-snippet-annotations=false 상태에서도 우회 (CVE 핵심)
✅ nginx가 inject된 파일을 실제 파싱 시도 (에러에 파일 경로 포함)
✅ 컨트롤러 SA 토큰 → kube-system secrets list 권한 확인
```

---

## 환경

| 항목 | 값 |
|------|-----|
| OS | Windows + WSL2 (Ubuntu) |
| Kubernetes | v1.30.8 (Minikube, docker driver) |
| ingress-nginx | **v1.11.4** (취약 버전) |
| Python | 3.12 (Stage 1 mock) |
| Minikube profile | `cve-2025-1974-lab` |

---

## Quick Start

### Stage 1 — Python mock

```bash
bash scripts/bootstrap.sh
make run       # collector + admission 서버 기동
make attack    # 공격 시뮬레이션
make stop
```

### Stage 2 — 클러스터 구축 (최초 1회)

```bash
bash scripts/bootstrap_stage2.sh
# 이후 재시작
make cluster-up
make cluster-status
```

### Stage 3 — PoC 실행

```bash
# ConfigMap 패치 없이 그대로 실행 (allow-snippet-annotations=false 기본값 유지)
# auth-snippet 이 이 검사를 우회하는 것이 CVE-2025-1974의 핵심
make poc

# 비교 시연 (A: 차단됨 vs B: 우회)
bash poc/run_comparison.sh
```

### Stage 5 — Red Team 공격 체인 (자동화)

```bash
# 개별 단계 실행 (port-forward 자동 관리)
make attack-enum      # T1: 파일 열거 (12개 경로)
make attack-token     # T2: SA 토큰 추출
make attack-lateral   # T3: Kubernetes API Lateral Movement

# 전체 체인 T1→T4 (리포트 자동 생성)
make attack-chain
# 결과: results/attack_result_<timestamp>.json / .md
```

### Stage 5 — Docker 공격자 파드 (클러스터 내부 실행)

```bash
# 이미지 빌드 + Minikube에 로드 (외부 레지스트리 불필요)
make docker-build

# 공격자 파드 배포 (port-forward 없이 서비스 DNS로 직접 접근)
make attacker-deploy

# 공격 결과 확인
make attacker-logs

# 정리
make attacker-delete
```

---

## 저장소 구조

```
.
├── Makefile                       # 공통 명령 (stage1/2/3/4/5)
├── Dockerfile                     # Red Team 공격자 파드 이미지
├── SETUP.md                       # 처음부터 끝까지 실행 순서
├── TROUBLESHOOTING.md             # 자주 깨지는 포인트와 해결
├── poc/
│   ├── cve_2025_1974_poc.py       # Stage 3 PoC 스크립트
│   ├── comparison.py              # Stage 3/4 A/B 비교 + SA 토큰 확인
│   ├── run_comparison.sh          # 비교 시연 헬퍼
│   ├── attack_chain.py            # Stage 5 Red Team 공격 체인 자동화
│   └── modules/
│       ├── file_enum.py           # 시나리오 A: 파일 열거
│       ├── token_extract.py       # 시나리오 B: SA 토큰 추출
│       ├── lateral_move.py        # 시나리오 C: Lateral Movement
│       └── reporter.py            # JSON + Markdown 결과 리포트
├── k8s/
│   └── attacker-pod.yaml          # 공격자 파드 + SA + RBAC
├── scripts/
│   ├── bootstrap.sh               # Stage 1 환경 구성 (Linux/WSL2)
│   ├── bootstrap.ps1              # Stage 1 환경 구성 (Windows)
│   ├── bootstrap_stage2.sh        # Stage 2 환경 구성 (클러스터)
│   └── stage3_run.sh              # Stage 3 PoC 실행 헬퍼
├── results/                       # 공격 결과 저장 (.gitignore)
└── docs/
    ├── goal.md
    ├── team_plan.md               # Purple Team 5인 역할 분배
    ├── proposal_red_team.md       # Red Team 공격 실험 계획
    ├── attack_report.md           # Red Team → Blue/Detection 인수인계 보고서
    └── commit-convention.md
```

---

## Git Workflow

- Conventional Commits 스타일
- 논리 단위별로 작게 커밋
- `--amend` / `rebase -i` 금지
- 민감정보 커밋 금지

## Verification

```bash
make check          # 전체 환경 점검
make cluster-status # 클러스터 + webhook 상태
make webhook-info   # admission webhook 상세
```

## Cleanup

```bash
make cluster-down    # 클러스터 중지 (데이터 유지)
make cluster-delete  # 클러스터 삭제
```
