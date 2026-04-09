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
| Stage 3 | admission webhook 비인증 접근 + auth-snippet 우회 재현 | 진행 중 |
| Stage 4 | 토큰 탈취 → Kubernetes API 접근 체인 완성 | 예정 |

## Stage 3 현재 달성 수준

- ✅ webhook 인증 없이 AdmissionReview 처리
- ✅ configuration-snippet → allow-snippet-annotations=false로 차단 확인
- ✅ auth-snippet → 취약 설정(true)에서 차단 없이 수용
- ✅ nginx가 inject된 파일을 실제 파싱 시도 (에러에 파일 경로 포함)
- ⚠️ webhook 응답에서 파일 내용 직접 추출 — 미완성 (nginx 에러 형식 특성)