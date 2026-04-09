# Goal

목표는 CVE-2025-1974 (IngressNightmare) 학습을 위한 로컬 전용 Kubernetes 랩 환경을 구축하고,
취약점 동작 원리를 단계별로 재현하는 것이다.

원칙:
- 로컬 단일 머신 (Minikube, 격리 환경)
- 외부 노출 금지
- 실제 exploit/무기화/외부 대상 공격 없음

## 단계별 목표

| 단계 | 목표 | 상태 |
|------|------|------|
| Stage 1 | Python mock 시뮬레이션으로 admission 흐름 이해 | 완료 |
| Stage 2 | Minikube + ingress-nginx v1.11.4 (취약 버전) 클러스터 구축 | 완료 |
| Stage 3 | admission webhook 비인증 접근 + auth-snippet 우회 재현 | 완료 |
| Stage 4 | SA 토큰 확인 + Kubernetes API 접근 체인 | 완료 |

## 달성 수준

- ✅ webhook 인증 없이 AdmissionReview 처리
- ✅ configuration-snippet → allow-snippet-annotations=false로 차단 확인 (기준선)
- ✅ auth-snippet → allow-snippet-annotations=false 상태에서도 우회 (CVE-2025-1974 핵심)
- ✅ nginx가 inject된 파일을 실제 파싱 시도 (에러에 파일 경로 포함)
- ✅ 컨트롤러 SA 토큰 → kube-system secrets list 권한 확인

## CVE-2025-1974 공격 체인

```
공격자 (클러스터 내 임의 파드)
  │
  ▼ POST /networking/v1/ingresses (인증 없음)
admission webhook (ingress-nginx-controller-admission:443)
  │
  ├─ configuration-snippet → allow-snippet-annotations 검사 → 차단 ✗
  │
  └─ auth-snippet          → 검사 없이 통과 → nginx.conf 주입 ✓
       │
       ▼ nginx -t (config test)
       include /var/run/secrets/kubernetes.io/serviceaccount/token;
       │
       ├─ 파일 열림 → 파싱 에러 → 에러 메시지가 webhook HTTP 응답으로 반환
       │
       └─ SA 토큰으로 kubectl get secrets -A (kube-system 포함) 가능
```

## 수정 버전

ingress-nginx >= 1.11.5 / >= 1.12.1:
- auth-snippet도 configuration-snippet과 동일하게 allow-snippet-annotations 검사 적용
