# CVE-2025-1974 Local Lab

이 저장소는 CVE-2025-1974 관련 구조를 학습하기 위한 로컬 Kubernetes 실습 프로젝트다.

현재 단계의 범위는 환경구축만 포함한다.
즉, Minikube 기반의 격리된 로컬 클러스터를 만들고, ingress-nginx 및 샘플 애플리케이션을 배포하며, admission 관련 구성을 관찰할 수 있는 상태까지만 준비한다.

이 단계에서 포함하지 않는 것:
- PoC 실행
- exploit 코드 작성/수정
- AdmissionReview 요청 생성/전송
- 공격 성공 여부 검증
- 외부 대상 테스트

## Safety

- 로컬 단일 머신에서만 실행한다.
- 외부에 노출되는 설정을 기본값으로 사용하지 않는다.
- 다른 Kubernetes 컨텍스트를 사용하지 않는다.
- 민감정보와 자격증명은 저장소에 포함하지 않는다.

## Prerequisites

- Docker
- Minikube
- kubectl
- bash
- make
- git

## Quick Start

```bash
cp .env.example .env
make bootstrap
make start
make install-ingress
make deploy-sample
make check
```

## Expected Outcome
- `cve-2025-1974-lab` Minikube profile 생성
- ingress-nginx namespace 준비
- `lab` namespace 준비
- ingress-nginx 관련 리소스 배포
- sample app/service/ingress 배포
- 환경 점검 스크립트 통과

## Git Workflow

이 프로젝트는 변경 이력을 학습 자료로 활용한다.

원칙:

- 한 번에 큰 변경을 하지 않는다
- 의미 있는 작은 단위로 나눈다
- 각 단계는 Conventional Commits 스타일로 기록한다

예시:
```
chore: initialize repository scaffold
build: add minikube startup scripts
feat: add ingress-nginx install flow
feat: add sample app manifests
docs: add safety and architecture notes
```
## Verification
```
kubectl config current-context
minikube profile list
kubectl get ns
kubectl get pods -A
kubectl get validatingwebhookconfigurations
kubectl get ingress -n lab
```

## Cleanup
```
make cleanup
```
## Next Step Checkpoints

다음 단계로 넘어가기 전에 아래를 만족해야 한다.

- Minikube profile이 고정되어 있다
- 현재 kubectl context가 예상한 로컬 컨텍스트다
- ingress-nginx가 정상 기동 중이다
- sample app/service/ingress가 배포되어 있다
- cleanup이 정상 동작한다