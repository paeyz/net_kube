# Team Plan — CVE-2025-1974 Purple Team Lab

> 공격-방어-탐지 실습 / 5인 역할 분배 + 확장 개발 로드맵

---

## 팀 구조

```
┌─────────────────────────────────────────────────────┐
│              CVE-2025-1974 Purple Team Lab           │
│                                                     │
│  🔴 Red Team      🔵 Blue Team     🟡 Detection     │
│  (공격 확장)      (방어 구현)       (탐지 구현)      │
│                                                     │
│     1명               2명              2명           │
└─────────────────────────────────────────────────────┘
```

---

## 현재 상태

| 단계 | 내용 | 상태 |
|------|------|------|
| Stage 1 | Python mock 시뮬레이션 | ✅ 완료 |
| Stage 2 | Minikube + ingress-nginx v1.11.4 클러스터 구축 | ✅ 완료 |
| Stage 3 | webhook 비인증 접근 + auth-snippet 우회 재현 | ✅ 완료 |
| Stage 4 | SA 토큰 확인 + Kubernetes API 접근 체인 | ✅ 완료 |

PoC 재현은 "환경 이해"다. 진짜 프로젝트는 여기서 시작한다.

---

## 역할별 구체 작업

### 🔴 Red Team — 1명 (공격 확장)

PoC를 실제 공격 체인으로 완성한다.

| 작업 | 내용 | 기술 |
|------|------|------|
| 파일 탈취 자동화 | 임의 경로 파일 → webhook 에러 파싱 | Python |
| Lateral Movement | 탈취한 SA 토큰 → API 서버 → secret 열람 → 다른 SA 탈취 | kubectl, Python |
| Load Module 시뮬레이션 | `load_module /tmp/malicious.so;` → RCE 경로 문서화 (실행 X) | 문서화 |
| 공격 자동화 스크립트 | `make attack-chain` 한 번에 전체 체인 실행 | Bash/Python |

**산출물**

```
poc/attack_chain.py    # webhook → 토큰 탈취 → API 접근 자동화
docs/attack_report.md  # 공격 흐름 + 증거 스크린샷 포함 보고서
```

---

### 🔵 Blue Team — 2명 (방어 구현)

#### B1 — 패치 & 업그레이드 담당

| 작업 | 내용 |
|------|------|
| ingress-nginx 업그레이드 | v1.11.4 → v1.11.5 후 동일 PoC 재실행 → 차단 확인 |
| before/after 비교 | 패치 전/후 결과를 동일 스크립트로 기록 |
| Helm values 하드닝 | `allowSnippetAnnotations=false` 강제, `failurePolicy=Fail` 설정 |

#### B2 — 네트워크 정책 & RBAC 담당

| 작업 | 내용 |
|------|------|
| NetworkPolicy | webhook(8443) 접근을 kube-apiserver IP만 허용 |
| RBAC 최소 권한 | ingress-nginx SA에서 불필요한 권한 제거 |
| OPA/Gatekeeper | Ingress 어노테이션 whitelist 정책 (auth-snippet 차단) |

NetworkPolicy 작성 예시:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-webhook-from-apiserver-only
  namespace: ingress-nginx
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: controller
  policyTypes:
  - Ingress
  ingress:
  - ports:
    - port: 8443
    from:
    - ipBlock:
        cidr: <apiserver-cidr>
```

**산출물**

```
defense/networkpolicy.yaml     # webhook 접근 제한
defense/rbac-patch.yaml        # 최소 권한 RBAC
defense/gatekeeper-policy.yaml # 어노테이션 whitelist
docs/defense_report.md         # 방어 적용 전/후 비교 보고서
```

---

### 🟡 Detection Team — 2명 (탐지 구현)

#### D1 — Falco 룰 + 실시간 알림 담당

| 작업 | 내용 |
|------|------|
| Falco 설치 | Minikube에 Falco DaemonSet 배포 |
| 커스텀 룰 작성 | 아래 3가지 이벤트 탐지 |
| Slack 알림 연동 | Falco → Alertmanager → Slack |

작성할 Falco 룰:

```yaml
# 1) webhook 비인증 직접 접근
- rule: Ingress Webhook Unauthenticated Access
  desc: admission webhook에 system: 계정 외 주체가 직접 접근
  condition: >
    k8s_audit and
    ka.target.resource = "ingresses" and
    ka.uri contains "/networking/v1/ingresses" and
    not ka.user.name startswith "system:"
  output: "Suspicious webhook access (user=%ka.user.name src=%ka.source.ip)"
  priority: CRITICAL

# 2) nginx가 SA 토큰 파일 읽음
- rule: Nginx Read ServiceAccount Token
  desc: nginx 프로세스가 serviceaccount 토큰 파일에 접근
  condition: >
    open_read and
    proc.name = "nginx" and
    fd.name contains "serviceaccount/token"
  output: "nginx read SA token (pod=%k8s.pod.name file=%fd.name)"
  priority: CRITICAL

# 3) 컨테이너 내 curl/wget으로 API 서버 접근
- rule: Container Curl Kubernetes API
  desc: 컨테이너 내부에서 Kubernetes API 서버에 직접 HTTP 요청
  condition: >
    spawned_process and
    proc.name in (curl, wget) and
    proc.args contains "kubernetes.default"
  output: "API access from container (pod=%k8s.pod.name cmd=%proc.cmdline)"
  priority: WARNING
```

#### D2 — 로그 수집 + 대시보드 담당

| 작업 | 내용 |
|------|------|
| Loki + Promtail | nginx 에러 로그 수집 파이프라인 구성 |
| Grafana 대시보드 | webhook 요청 수, 에러율, 비정상 어노테이션 패턴 시각화 |
| 공격 vs 정상 비교 | 공격 실행 전후 로그 diff 분석 문서화 |

**산출물**

```
monitoring/falco-rules.yaml        # 커스텀 탐지 룰
monitoring/grafana-dashboard.json  # 대시보드 export
monitoring/loki-config.yaml        # 로그 수집 설정
docs/detection_report.md           # "이 공격은 어디서 탐지됐나" 분석
```

---

## 기술 스택

| 영역 | 도구 | 이유 |
|------|------|------|
| 런타임 탐지 | Falco | 컨테이너 내 syscall 수준 탐지 |
| 로그 수집 | Loki + Promtail | 경량, Minikube에서 동작 |
| 시각화 | Grafana | Loki/Prometheus 연동 |
| 정책 | OPA/Gatekeeper | Ingress 어노테이션 화이트리스트 |
| 네트워크 가시성 | Hubble (Cilium) 또는 tcpdump | webhook 트래픽 패킷 확인 |
| 이미지 스캔 | Trivy | v1.11.4 vs v1.11.5 취약점 비교 |

---

## 개발 로드맵

```
Phase 1 (완료)  — PoC 재현                        ✅
Phase 2 (2주)   — 공격/방어/탐지 각자 구현
Phase 3 (1주)   — 통합 시나리오 실행 (라이브 훈련)
Phase 4 (1주)   — 보고서 + 발표
```

---

## Phase 3 — 통합 시나리오 (핵심)

5명이 동시에 역할을 수행하는 라이브 공격 훈련이다.

```
1. Blue Team   클러스터 시작 + 방어 정책 적용
      ↓
2. Detection   Falco + Grafana 모니터링 시작
      ↓
3. Red Team    make attack-chain 실행
      ↓
4. Detection   알림 수신 + 로그에서 공격 흔적 찾기 (타임라인 기록)
      ↓
5. Blue Team   NetworkPolicy로 차단 적용
      ↓
6. Red Team    재시도 → 차단 확인
      ↓
7. 전체        타임라인 + 근거 정리 → 보고서 작성
```

이 시나리오가 프로젝트의 핵심이다. 각 팀이 서로의 행동에 반응하는 흐름을 기록하는 것이 목표다.

---

## 지금 당장 시작할 것

개인 공부 단계에서 각자 반드시 해볼 것:

1. `bash poc/run_comparison.sh` — 직접 눈으로 A/B 차이 확인
2. `kubectl exec`으로 SA 토큰 읽어보기
3. CVE 원문 읽기: [kubernetes/ingress-nginx#12375](https://github.com/kubernetes/ingress-nginx/issues/12375)
4. 자신이 맡을 역할의 도구 설치 + 튜토리얼 1개 완료

---

## 최종 산출물 목록

```
poc/
  attack_chain.py          # Red: 전체 공격 자동화
defense/
  networkpolicy.yaml       # Blue B2
  rbac-patch.yaml          # Blue B2
  gatekeeper-policy.yaml   # Blue B2
monitoring/
  falco-rules.yaml         # Detection D1
  grafana-dashboard.json   # Detection D2
  loki-config.yaml         # Detection D2
docs/
  attack_report.md         # Red
  defense_report.md        # Blue
  detection_report.md      # Detection
  timeline.md              # Phase 3 통합 시나리오 실행 기록
```
