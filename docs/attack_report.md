# Attack Report — CVE-2025-1974 (IngressNightmare)

> **작성자**: Red Team  
> **환경**: 로컬 Minikube 격리 클러스터 (`cve-2025-1974-lab`)  
> **대상**: ingress-nginx v1.11.4 (취약 버전)  
> **목적**: Blue/Detection 팀 인수인계 — 공격 흐름 + IOC + 방어/탐지 힌트

---

## 1. 공격 개요

CVE-2025-1974 (IngressNightmare)는 ingress-nginx admission webhook에서 `auth-snippet` 어노테이션이 `allow-snippet-annotations=false` 설정을 우회하는 취약점이다.

**공격 체인 요약**:

```
클러스터 내 임의 파드 (또는 port-forward)
  │
  ▼ [T1] POST /networking/v1/ingresses — 인증 없음
  admission webhook (ingress-nginx-controller-admission:443)
  │
  ├─ auth-snippet: include <경로>; → allow 검사 없이 nginx.conf 주입 (CVE 핵심)
  │    nginx -t 실행 → 파일 파싱 시도 → 에러 메시지로 접근 가능 경로 노출
  │
  ▼ [T2] SA 토큰 추출
  kubectl exec -n ingress-nginx <controller-pod> -- cat /var/run/secrets/.../token
  │
  ▼ [T3] Kubernetes API Lateral Movement
  kubectl --token=<탈취된_토큰> get secrets -A
  → kube-system secrets 열람 가능 → 다른 SA 토큰 탈취 → 권한 상승 확인
```

---

## 2. 환경 정보

| 항목 | 값 |
|------|-----|
| OS | Windows + WSL2 (Ubuntu) |
| Kubernetes | v1.30.8 (Minikube, docker driver) |
| ingress-nginx | **v1.11.4** (취약 버전, CVE-2025-1974) |
| 수정 버전 | v1.11.5 이상 (auth-snippet도 동일 검사 적용) |
| Minikube 프로파일 | `cve-2025-1974-lab` |
| webhook 엔드포인트 | `ingress-nginx-controller-admission.ingress-nginx.svc:443` |

---

## 3. 공격 단계별 결과

### T1 — 파일 열거 (시나리오 A)

`auth-snippet: include <경로>;` 주입 후 webhook 에러 메시지에서 접근 가능 경로를 열거했다.

**접근 가능 경로** (nginx가 실제 열기 시도):
```
/var/run/secrets/kubernetes.io/serviceaccount/token      ← SA 토큰
/var/run/secrets/kubernetes.io/serviceaccount/namespace  ← 네임스페이스
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt     ← 클러스터 CA
/etc/hosts                                               ← 내부 DNS
/etc/resolv.conf                                         ← DNS 서버
/etc/passwd                                              ← 사용자 정보
/proc/self/environ                                       ← 환경변수
/etc/hostname                                            ← 호스트명
```

**핵심 증거**: webhook 응답 메시지에 파일 경로가 포함됨 → nginx가 컨트롤러 파드 내부에서 실제로 파일에 접근했음이 증명됨.

---

### T2 — SA 토큰 추출 (시나리오 B)

```bash
# kubectl exec으로 직접 추출
kubectl exec -n ingress-nginx <controller-pod> -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

- **ServiceAccount**: `ingress-nginx/ingress-nginx`
- **JWT 헤더**: `{"alg":"RS256","kid":"<키 ID>"}`
- **권한**: kube-system 네임스페이스의 secrets list 포함

---

### T3 — Kubernetes API Lateral Movement (시나리오 C)

**Level 1 — 정보 수집**:
```bash
kubectl --token=<token> get secrets -A        # ← kube-system 포함 가능
kubectl --token=<token> get configmaps -A
kubectl --token=<token> get pods -A
kubectl --token=<token> get serviceaccounts -A
```

**Level 2 — 다른 SA 토큰 탈취**:
- kube-system 시크릿 중 `kubernetes.io/service-account-token` 타입 탐색
- 권한이 높은 SA 토큰 획득 가능 여부 확인

**Level 3 — 권한 상승 확인** (실제 실행 없음, can-i만):
```bash
kubectl --token=<token> auth can-i create pods -n kube-system
kubectl --token=<token> auth can-i create clusterrolebindings
kubectl --token=<token> auth can-i list secrets --all-namespaces
```

---

## 4. 공격 재현 방법 (Blue/Detection 팀 참조)

### 전제 조건
```bash
# 클러스터 실행 확인
make cluster-up
make cluster-status

# port-forward (외부에서 실행 시)
kubectl port-forward svc/ingress-nginx-controller-admission 8443:443 -n ingress-nginx &
```

### 개별 단계 실행
```bash
make attack-enum      # T1: 파일 열거만
make attack-token     # T2: 토큰 추출만
make attack-lateral   # T3: Lateral Movement만
make attack-chain     # T1→T4 전체 자동화
```

### 클러스터 내부 파드로 실행 (현실적 시나리오)
```bash
make docker-build       # Docker 이미지 빌드 + minikube image load
make attacker-deploy    # 공격자 파드 배포 (port-forward 불필요)
make attacker-logs      # 실행 결과 확인
make attacker-delete    # 파드 정리
```

### 결과 파일
```
results/attack_result_<timestamp>.json   # 상세 데이터
results/attack_result_<timestamp>.md     # 읽기 쉬운 요약
```

---

## 5. IOC (Indicators of Compromise)

### 5-1. 비정상 Ingress 어노테이션 패턴

```yaml
# 탐지 대상 어노테이션
nginx.ingress.kubernetes.io/auth-snippet: "include /var/run/secrets/..."
nginx.ingress.kubernetes.io/auth-snippet: "include /proc/self/..."
nginx.ingress.kubernetes.io/auth-snippet: "include /etc/..."
```

**탐지 포인트**: Ingress 생성/수정 시 `auth-snippet` 값에 `include` 지시어 포함 여부.

### 5-2. nginx 비정상 파일 접근

```
# nginx 프로세스가 접근하면 안 되는 경로
/var/run/secrets/kubernetes.io/serviceaccount/token
/proc/self/environ
/etc/shadow
```

**탐지 포인트**: Falco 룰 — `proc.name = "nginx"` && `fd.name contains "serviceaccount"`.

### 5-3. ingress-nginx SA 토큰의 비정상 API 호출

정상 동작 범위를 벗어난 API 호출:
```
GET /api/v1/namespaces/kube-system/secrets  ← 공격 시그니처
GET /api/v1/secrets (all namespaces)
```

**탐지 포인트**: kube-apiserver 감사 로그에서 `system:serviceaccount:ingress-nginx:ingress-nginx` 의 kube-system secrets 접근.

### 5-4. 공격자 파드 실행 패턴

```yaml
# attacker-pod에서 관찰되는 네트워크 패턴
TCP: <attacker-pod-IP> → ingress-nginx-controller-admission:443
POST /networking/v1/ingresses (반복, 12회 이상)
```

---

## 6. 수정 방법 (Blue Team 참조)

### 즉시 적용 (패치)
```bash
# ingress-nginx v1.11.5 이상으로 업그레이드
helm upgrade ingress-nginx ingress-nginx/ingress-nginx \
  --version 4.10.1 \
  -n ingress-nginx \
  --set controller.image.tag="v1.11.5"
```

### 단기 완화
```bash
# auth-snippet을 차단하는 OPA/Gatekeeper 정책 적용
# → docs/defense_report.md 참조 (Blue Team B2 산출물)

# NetworkPolicy로 webhook 접근을 apiserver로만 제한
kubectl apply -f defense/networkpolicy.yaml
```

### 패치 검증
```bash
# 패치 후 동일 PoC 실행 → auth-snippet도 차단 확인
make poc-step3    # allowed=false 응답 확인
```

---

## 7. 실험 타임라인

> 이 섹션은 Phase 3 통합 시나리오 실행 시 채워진다.

| 시각 | 팀 | 이벤트 |
|------|-----|--------|
| T+0:00 | Blue | 클러스터 시작 + 기본 방어 정책 적용 |
| T+0:05 | Detection | Falco + Grafana 모니터링 시작 |
| T+0:10 | Red | `make attack-chain` 실행 |
| T+0:11 | Detection | (탐지 알림 수신 여부 기록) |
| T+0:15 | Blue | NetworkPolicy 차단 적용 |
| T+0:20 | Red | 재시도 → 차단 확인 |
| T+0:30 | All | 타임라인 + 근거 정리 |

---

## 8. 다음 단계 — Blue/Detection 팀

Red Team 공격 체인이 완성됐다. 각 팀은 다음을 진행한다.

**Blue Team (B1 — 패치)**:
- `make poc` 실행 → 현재 우회 확인
- ingress-nginx v1.11.5로 업그레이드
- `make poc` 재실행 → 차단 확인
- `docs/defense_report.md` 작성

**Blue Team (B2 — 네트워크/RBAC)**:
- `defense/networkpolicy.yaml` 작성 및 적용
- `defense/rbac-patch.yaml` 작성 (ingress-nginx SA 최소 권한)
- OPA Gatekeeper로 auth-snippet 어노테이션 차단

**Detection Team (D1 — Falco)**:
- `monitoring/falco-rules.yaml` 작성
- `make attack-chain` 실행 중 Falco 알림 수신 확인
- Slack 알림 연동

**Detection Team (D2 — Loki/Grafana)**:
- `monitoring/loki-config.yaml` 작성
- 공격 실행 전후 nginx 로그 diff 분석
- `monitoring/grafana-dashboard.json` 작성
