# SETUP — CVE-2025-1974 IngressNightmare Purple Team Lab

> **목적**: CVE-2025-1974 (IngressNightmare) 취약점을 로컬 격리 환경에서 재현하고,
> Red/Blue/Detection 팀이 각자 역할을 실습하는 가이드.
>
> **안전 원칙**: 로컬 Minikube 격리 환경 전용 (`127.0.0.1`). 외부 대상 없음. 무기화 없음.

---

## 전체 진행 상태

| 단계 | 내용 | 담당 | 상태 |
|------|------|------|------|
| Stage 1 | Python mock 시뮬레이션 | 전체 | ✅ 완료 |
| Stage 2 | Minikube + ingress-nginx v1.11.3 클러스터 | 전체 | ✅ 완료 |
| Stage 3 | webhook 비인증 + auth-snippet 우회 PoC | Red | ✅ 완료 |
| Stage 4 | SA 토큰 탈취 + Kubernetes API 접근 | Red | ✅ 완료 |
| **Stage 5** | **공격 체인 자동화 + Docker 인수인계** | **Red** | **✅ 완료** |
| Stage 6 | 방어 구현 (M1~M4) | Blue | 🔄 진행 예정 |
| Stage 7 | 탐지 구현 (D1~D4: Falco/Audit/Gatekeeper) | Detection | 🔄 진행 예정 |
| Stage 8 | Purple Team 통합 시나리오 실행 | 전체 | 예정 |

---

## 요구사항

| 항목 | 버전 | 확인 |
|------|------|------|
| OS | Windows + WSL2 (Ubuntu) | |
| Python | 3.11+ | `python3 --version` |
| Docker Desktop | 최신 | `docker --version` |
| Minikube | v1.34.0 | `minikube version` |
| kubectl | v1.30+ | `kubectl version --client` |
| helm | v3.x | `helm version` |
| git | 2.x | `git --version` |

---

## 빠른 시작 (최초 1회)

```bash
# 1. 클러스터 생성 (ingress-nginx v1.11.3 포함, allow-snippet-annotations=true 자동 설정)
bash scripts/bootstrap_stage2.sh

# 2. 클러스터 확인
make cluster-status
```

---

## Red Team — 공격 체인 실행

### 로컬 실행 (port-forward 방식)

```bash
# 클러스터 시작
make cluster-up

# port-forward는 attack-* 타깃이 자동으로 관리함

# 개별 단계
make attack-enum      # T1: 파일 열거 (12개 경로)
make attack-token     # T2: SA 토큰 추출 + JWT 파싱
make attack-lateral   # T3: Kubernetes API Lateral Movement

# 전체 자동화 (T1→T4, 리포트 자동 생성)
make attack-chain
```

### 결과 확인

```bash
ls results/attack_result_*.json   # JSON 상세 데이터
ls results/attack_result_*.md     # Markdown 요약
cat docs/attack_report.md         # Blue/Detection 팀 인수인계 보고서
```

### Docker 공격자 파드 (클러스터 내부 실행 — 현실적 시나리오)

```bash
# 이미지 빌드 + Minikube에 로드 (외부 레지스트리 불필요)
make docker-build

# 공격자 파드 배포 (port-forward 없이 서비스 DNS 직접 접근)
make attacker-deploy

# 실행 결과 확인 (공격 체인 로그)
make attacker-logs

# 정리
make attacker-delete
```

---

## Blue Team — 방어 구현

### M1: Admission Webhook 비활성화

```bash
make defense-m1          # webhook 비활성화
make attack-chain        # → webhook 연결 실패 확인
make defense-m1-restore  # webhook 복원
```

### M2: NetworkPolicy (Calico — 별도 프로파일 필요)

```bash
# Calico CNI 프로파일로 클러스터 재생성 필요
minikube start -p cve-2025-1974-netpol \
  --network-plugin=cni --cni=calico --wait all

# NetworkPolicy 적용
make defense-m2

# 공격자 파드로 검증 (in-cluster direct POST → 차단 확인)
make attacker-deploy
make attacker-logs       # connection refused 확인
make defense-m2-remove   # 제거
```

### M3: ValidatingAdmissionPolicy (kubectl apply 경로 차단)

```bash
make defense-m3

# 검증: kubectl apply로 악성 Ingress 시도
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-vap
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/auth-snippet: "include /etc/passwd;"
spec:
  ingressClassName: nginx
  rules:
  - host: test.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: svc
            port:
              number: 80
EOF
# → Error: ValidatingAdmissionPolicy 차단 확인

make defense-m3-remove   # 제거
```

### M4: RBAC 최소 권한 (Lateral Movement 범위 축소)

```bash
make defense-m4

# 검증: 탈취된 SA 토큰으로 kube-system Secrets 접근 → Forbidden
TOKEN=$(kubectl exec -n ingress-nginx \
  $(kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller -o name | head -1) \
  -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token="$TOKEN" get secrets -n kube-system   # → Forbidden (성공)
kubectl --token="$TOKEN" get secrets -n ingress-nginx  # → OK (정상 동작)
```

### 전체 방어 정책 제거 (원상복구)

```bash
make defense-restore
```

---

## Detection Team — 탐지 구현

### 일괄 설치

```bash
make detect-setup   # Falco + Gatekeeper + Audit Log 한 번에 설치
```

### Falco (D1/D3/D4)

```bash
make detect-falco         # Falco DaemonSet 설치
make detect-falco-rules   # CVE-2025-1974 커스텀 룰 적용

# 공격 실행 + 탐지 확인
make attack-chain &       # 백그라운드 공격
make detect-falco-logs    # 실시간 알림 확인
# → CVE-2025-1974 관련 CRITICAL 알림 확인
```

**탐지 시나리오**:
- **D1**: 파드 → webhook 8443 direct connect (`evt.type=connect`)
- **D3**: nginx 프로세스가 SA 토큰 파일 접근 (`fd.name contains serviceaccount/token`)
- **D4**: 컨테이너 내부 kubectl/curl → Kubernetes API 접근

### OPA/Gatekeeper (D2)

```bash
make detect-gatekeeper         # OPA/Gatekeeper 설치
make detect-gatekeeper-policy  # D2 정책 적용 (warn 모드)

# violation 확인 (make attack-chain 실행 후)
make detect-gatekeeper-violations

# deny 모드 전환: monitoring/gatekeeper-constraint.yaml에서
#   enforcementAction: warn → deny 로 변경 후
kubectl apply -f monitoring/gatekeeper-constraint.yaml
```

**탐지 시나리오**:
- **D2**: auth-snippet annotation에 `include`, `load_module`, `/var/run/secrets/` 포함 시 violation/deny

### Kubernetes Audit Log (D2/D4)

```bash
make detect-audit       # kube-apiserver Audit Log 활성화

# 공격 실행 후 로그 확인
make attack-chain &
make detect-audit-tail  # 실시간 audit log 스트리밍

# 확인 항목:
# D2: requestObject.metadata.annotations["auth-snippet"] 에 위험 패턴
# D4: user.username=system:serviceaccount:ingress-nginx:... 의 kube-system secrets 접근
```

### 탐지 도구 전체 상태 확인

```bash
make detect-status
```

---

## Purple Team 통합 시나리오 (Phase 3)

5인이 동시에 역할을 수행하는 라이브 훈련 순서:

```
1. Blue Team   → make cluster-up + make detect-setup
2. Detection   → make detect-falco-logs (별도 터미널에서 모니터링 시작)
3. Red Team    → make attack-chain (또는 make attacker-deploy)
4. Detection   → Falco 알림 수신 + Audit Log 확인 → 타임라인 기록
5. Blue Team   → make defense-m3 (VAP 적용)
6. Red Team    → 재시도 → VAP 차단 확인
7. Blue Team   → make defense-m4 (RBAC 축소)
8. Red Team    → make attack-lateral → blast radius 축소 확인
9. 전체        → docs/timeline.md 작성
```

---

## 파일 구조

```
.
├── Dockerfile                     # Red Team 공격자 파드 이미지
├── Makefile                       # 전체 타깃 (Red/Blue/Detection)
├── poc/
│   ├── attack_chain.py            # T1→T4 전체 공격 자동화
│   ├── cve_2025_1974_poc.py       # Stage 3 PoC (단계별)
│   ├── comparison.py              # A/B 비교 시연
│   └── modules/                   # 공격 모듈 (file_enum, token_extract, lateral_move, reporter)
├── defense/
│   ├── m1-webhook-disable.sh      # M1: webhook 비활성화
│   ├── m2-networkpolicy.yaml      # M2: NetworkPolicy (Calico)
│   ├── m3-vap.yaml                # M3: ValidatingAdmissionPolicy
│   └── m4-rbac-hardened.yaml      # M4: RBAC 최소 권한
├── monitoring/
│   ├── falco-rules.yaml           # Falco 커스텀 룰 (D1/D3/D4)
│   ├── audit-policy.yaml          # kube-apiserver Audit Log 정책 (D2/D4)
│   ├── gatekeeper-template.yaml   # OPA/Gatekeeper ConstraintTemplate (D2)
│   └── gatekeeper-constraint.yaml # OPA/Gatekeeper Constraint (D2)
├── k8s/
│   └── attacker-pod.yaml          # 공격자 파드 + SA + RBAC
├── scripts/
│   ├── bootstrap_stage2.sh        # 클러스터 최초 구성
│   ├── setup_falco.sh             # Falco 설치 + 룰 적용
│   ├── setup_gatekeeper.sh        # OPA/Gatekeeper 설치 + 정책
│   └── setup_audit_log.sh         # kube-apiserver Audit Log 활성화
├── results/                       # 공격 결과 (.gitignore)
└── docs/
    ├── team_plan.md               # 5인 역할 분배 + 로드맵
    ├── proposal_red_team.md       # Red Team 공격 실험 계획
    ├── attack_report.md           # Red Team → Blue/Detection 인수인계 보고서
    └── goal.md
```

---

## 자주 쓰는 명령 참조

```bash
# 클러스터
make cluster-up / cluster-down / cluster-status

# Red Team
make attack-chain       # 전체 공격 자동화
make attacker-deploy    # Docker 공격자 파드

# Blue Team
make defense-m3         # VAP 적용 (가장 빠른 방어)
make defense-restore    # 전체 복구

# Detection
make detect-setup       # 탐지 도구 일괄 설치
make detect-falco-logs  # Falco 실시간 알림
make detect-status      # 전체 상태
```
