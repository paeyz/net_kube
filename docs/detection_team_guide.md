# Detection Team 가이드라인 — CVE-2025-1974 IngressNightmare

> **작성자**: Red Team (paeyz) → Detection Team 인수인계  
> **리포**: https://github.com/paeyz/net_kube  
> **환경**: Windows + WSL2 / Minikube / ingress-nginx v1.11.3 (SHA 고정, allow-snippet-annotations=true)

---

## 한 줄 요약

> D1 + D3 (Falco) 가 이 CVE의 핵심 탐지 레이어다.  
> D2 (Gatekeeper / Audit Log) 는 kubectl apply 경로 보조 방어선이며, 직접 webhook POST 공격은 구조적으로 볼 수 없다.  
> 탐지팀의 목표는 "어디서 잡히고 어디서 안 잡히는지"를 직접 증명하는 것이다.

---

## 1. 탐지 도구 커버리지 전체 지도

```
공격자 파드
    │
    ├─ HTTPS POST → ingress-nginx webhook (port 8443)  ← kube-apiserver 미경유
    │       │
    │       └── nginx -t 실행 → SA token 파일 읽기
    │
    └─ kubectl --token  → kube-apiserver → secrets 조회
```

| 공격 단계 | 탐지 도구 | 시나리오 | 탐지 가능? |
|-----------|---------|---------|-----------|
| T1 webhook 직접 POST | Falco | D1 | ✅ |
| T1 nginx → SA token 파일 읽기 | Falco | D3 | ✅ |
| T1 직접 POST (annotation 패턴) | Gatekeeper / Audit Log | D2 | ❌ 구조적 불가 |
| T1 kubectl apply 경로 악성 annotation | Gatekeeper / Audit Log | D2 | ✅ |
| T3 탈취 SA 토큰으로 API 접근 | Audit Log | D4 | ✅ |

> **왜 D2가 직접 POST를 못 잡는가**  
> Gatekeeper와 Audit Log는 kube-apiserver를 통과한 요청만 본다.  
> CVE-2025-1974 공격은 webhook service에 직접 POST하므로 kube-apiserver를 완전히 우회한다.  
> 이는 탐지 실패가 아니라 **도구의 위치(위상)가 다른 것**이다.

---

## 2. 환경 준비

```bash
# 클러스터 시작 확인
make cluster-status

# 탐지 도구 일괄 설치 (Falco + Gatekeeper + Audit Log)
make detect-setup
```

설치 완료 후 상태 확인:

```bash
make detect-status
# Falco DaemonSet Running
# gatekeeper-system pods Running
# Audit Log 활성화 여부 확인
```

---

## 3. D1 — Webhook 직접 접근 탐지 (Falco)

### 탐지 원리

ingress-nginx 네임스페이스가 아닌 파드가 webhook service port(8443)에 직접 connect 하는 순간 Falco가 알림을 발생시킨다.

### 실습 순서

```bash
# 터미널 1 — Falco 실시간 알림 대기
make detect-falco-logs

# 터미널 2 — 공격 실행
make attack-enum
```

### 기대 출력 (Falco alert)

```
CRITICAL CVE-2025-1974: Direct webhook access from non-ingress pod
  proc.name=python3  fd.sport=8443  container.ns=default
```

### 탐지 안 될 경우 체크리스트

- [ ] `make detect-falco-rules` 로 커스텀 룰이 적용됐는지 확인
- [ ] `kubectl get pods -n falco` — DaemonSet Running 상태인지 확인
- [ ] port-forward로 실행 중인지 확인 (localhost:8443 접근이면 Falco 룰 조건 조정 필요)

---

## 4. D2 — Annotation 패턴 탐지 (Gatekeeper + Audit Log)

### 탐지 원리와 한계

Gatekeeper는 kube-apiserver의 admission webhook으로 동작한다.  
CVE 공격(직접 POST)은 kube-apiserver를 우회하므로 **D2로 탐지 불가**.  
D2는 `kubectl apply` 경로의 악성 Ingress를 차단/기록하는 **보조 방어선**이다.

### 실습 순서

**[D2-A] 정책 단위 테스트 — D2가 설계한 조건에서 동작하는지 확인**

> ⚠️ 이 단계는 공격 재현이 아닌 Gatekeeper 정책 자체의 동작 검증이다.  
> 보고서에 반드시 **"공격 재현 탐지 아님 — D2 정책 단위 테스트"** 로 분리해서 기록할 것.

```bash
# --dry-run=server: 리소스를 실제로 생성하지 않고 kube-apiserver → Gatekeeper 정책만 통과
kubectl apply --dry-run=server -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: d2-unit-test
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "http://127.0.0.1:9999/auth"
    nginx.ingress.kubernetes.io/auth-snippet: "include /etc/passwd;"
spec:
  ingressClassName: nginx
  rules:
  - host: d2-test.local
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
# warn 모드 → Warning: admission webhook ... violation 메시지 출력
# deny 모드 → Error from server: ... 차단
```

```bash
# violation 목록 확인
make detect-gatekeeper-violations
```

**[D2-B] 직접 POST 경로 — 탐지 불가 경계 확인**

```bash
# 공격 실행 (direct webhook POST)
make attack-enum

# violation 확인 → 없음
make detect-gatekeeper-violations
# → 결과 없음 (구조적 탐지 불가 — 이것이 이 실습의 핵심 발견)
```

**[D2-C] Gatekeeper deny 모드 전환 (선택)**

```bash
# monitoring/gatekeeper-constraint.yaml 에서
#   enforcementAction: warn  →  deny 로 변경

kubectl apply -f monitoring/gatekeeper-constraint.yaml

# 검증: --dry-run=server 로 차단 확인
kubectl apply --dry-run=server -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: d2-deny-test
  namespace: default
  annotations:
    nginx.ingress.kubernetes.io/auth-snippet: "include /etc/passwd;"
spec:
  ingressClassName: nginx
  rules:
  - host: d2-deny.local
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
# → Error from server: 차단 확인
```

---

## 5. D3 — nginx SA Token 파일 접근 탐지 (Falco)

### 탐지 원리

nginx 프로세스가 `/var/run/secrets/kubernetes.io/serviceaccount/token` 을 열 때 Falco syscall 수준에서 감지한다. nginx가 정상 동작 중 이 파일을 열 이유가 없다.

### 실습 순서

```bash
# 터미널 1 — Falco 실시간 알림 대기
make detect-falco-logs

# 터미널 2 — 공격 실행
make attack-enum
```

### 기대 출력 (Falco alert)

```
CRITICAL CVE-2025-1974: nginx process read SA token file
  proc.name=nginx  fd.name=/var/run/secrets/kubernetes.io/serviceaccount/token
```

> D1과 D3는 같은 `make attack-enum` 한 번으로 동시에 트리거된다.  
> Falco 로그에서 D1 alert이 먼저, D3 alert이 수 초 뒤에 뜨는 순서를 확인하면 공격 타임라인 재구성이 가능하다.

---

## 6. D4 — SA 토큰 탈취 후 API Lateral Movement 탐지 (Audit Log)

### 탐지 원리

T2에서 탈취한 SA 토큰으로 T3에서 `kubectl --token get secrets -A` 를 실행하면 이 요청은 kube-apiserver를 경유한다. Audit Log가 비정상적인 SA의 kube-system secrets 접근을 기록한다.

### 실습 순서

```bash
# 터미널 1 — Audit Log 스트리밍
make detect-audit-tail

# 터미널 2 — 전체 공격 체인 실행
make attack-chain
```

### 기대 출력 (Audit Log)

```
[list    ] system:serviceaccount:ingress-nginx:ingress-nginx  secrets/kube-system
[get     ] system:serviceaccount:ingress-nginx:ingress-nginx  secrets/kube-system/default-token-xxxxx
```

> `ingress-nginx` SA가 `kube-system` 네임스페이스의 secrets에 접근하는 것은 정상 동작이 아니다. 이 패턴 자체가 Lateral Movement 시그니처다.

---

## 7. 통합 시나리오 실행 (권장)

모든 탐지를 한 번에 확인하는 순서:

```bash
# [사전 준비]
make detect-setup           # 탐지 도구 일괄 설치

# [터미널 1] Falco 실시간 알림
make detect-falco-logs

# [터미널 2] Audit Log 스트리밍
make detect-audit-tail

# [터미널 3] 전체 공격 체인 실행
make attack-chain

# [공격 완료 후]
make detect-gatekeeper-violations   # D2 violation 확인
ls results/attack_result_*.md       # Red Team 공격 결과 리포트 확인
```

---

## 8. 탐지 결과 보고서 작성 가이드

Purple Team 실습 보고서에는 아래 항목을 포함한다.

### 8-1. 탐지 커버리지 표

| 탐지 ID | 공격 단계 | 도구 | 탐지 결과 | 비고 |
|---------|---------|------|---------|------|
| D1 | T1 webhook 직접 POST | Falco | ✅ / ❌ | alert 내용 기록 |
| D2-A | 정책 단위 테스트 (--dry-run=server) | Gatekeeper | ✅ / ❌ | **공격 재현 아님** — violation 메시지 기록 |
| D2-B | T1 webhook 직접 POST | Gatekeeper | ❌ 구조적 불가 | kube-apiserver 미경유, 이유 명시 필수 |
| D3 | T1 nginx → SA token 파일 읽기 | Falco | ✅ / ❌ | alert 내용 기록 |
| D4 | T3 SA 토큰 → API Lateral Movement | Audit Log | ✅ / ❌ | log 라인 기록 |

### 8-2. 타임라인 섹션 (예시)

```
HH:MM:SS  make attack-chain 시작
+0:02     D1 Falco alert — webhook 직접 접근
+0:03     D3 Falco alert — nginx SA token 파일 읽기
+0:15     T2 완료 — SA 토큰 탈취
+0:20     D4 Audit Log — ingress-nginx SA → kube-system secrets 접근
+0:30     공격 체인 종료
```

### 8-3. 탐지 공백 분석 섹션

> D2(Gatekeeper/Audit Log)는 kube-apiserver를 경유한 요청만 탐지할 수 있다.  
> CVE-2025-1974의 핵심 공격 경로(webhook 직접 POST)는 이 레이어를 우회한다.  
> **이 CVE에 대한 실질적 탐지는 Falco(D1+D3) 없이는 불가능하다.**  
> D2는 일반 사용자가 kubectl apply로 악성 Ingress를 배포하는 시도를 막는 보조 방어선으로 가치가 있다.

### 8-4. 권고 사항 섹션

- Falco DaemonSet을 모든 클러스터에 필수 배포할 것
- ingress-nginx 네임스페이스 외 파드의 webhook port(8443) 접근을 기본 차단 룰로 등록할 것
- `system:serviceaccount:ingress-nginx:*` SA의 kube-system secrets 접근을 Audit Log 알림으로 설정할 것

---

## 9. 관련 파일 위치

| 파일 | 용도 |
|------|------|
| `monitoring/falco-rules.yaml` | D1 / D3 / D4 Falco 커스텀 룰 |
| `monitoring/audit-policy.yaml` | kube-apiserver Audit Log 정책 (D2/D4) |
| `monitoring/gatekeeper-template.yaml` | OPA/Gatekeeper ConstraintTemplate (D2) |
| `monitoring/gatekeeper-constraint.yaml` | OPA/Gatekeeper Constraint — warn/deny 전환 가능 |
| `scripts/setup_falco.sh` | Falco 설치 + 룰 적용 자동화 |
| `scripts/setup_gatekeeper.sh` | OPA/Gatekeeper 설치 + 정책 적용 자동화 |
| `scripts/setup_audit_log.sh` | kube-apiserver Audit Log 활성화 자동화 |
| `docs/red_team_handoff.md` | Red Team 공격 방식 전체 설명 (공격자 시점 이해용) |

---

## 10. 참고

- Falco 공식 문서: https://falco.org/docs/
- OPA/Gatekeeper: https://open-policy-agent.github.io/gatekeeper/
- CVE 원문: https://github.com/kubernetes/ingress-nginx/issues/12375
- Wiz Research: https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities
