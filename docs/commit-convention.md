# Commit Convention

이 저장소는 학습 가능한 변경 이력을 남기는 것을 목표로 한다.

## Rules

1. 하나의 커밋에는 하나의 주제만 담는다.
2. 파일이 많아도 논리적으로 같은 작업일 때만 함께 묶는다.
3. 문서와 코드가 강하게 연결된 경우에만 같이 커밋한다.
4. 민감정보, kubeconfig, 토큰, 비밀값은 절대 커밋하지 않는다.
5. 자동 생성물은 필요한 경우에만 포함한다.

## Format

Conventional Commits 형식을 사용한다.

- `chore:` 초기화, 정리, 구조 작업
- `build:` 환경, 스크립트, 설치 흐름
- `feat:` 기능 추가
- `docs:` 문서 추가/수정
- `refactor:` 동작 유지 리팩터링
- `test:` 검증 스크립트, 체크 추가

## Examples

- `chore: initialize lab repository scaffold`
- `build: add minikube bootstrap scripts`
- `feat: add ingress-nginx installation workflow`
- `feat: add sample app and ingress manifests`
- `docs: add architecture and safety checklist`
- `test: add environment verification script`

## Recommended Commit Units

좋은 예:
- `.env.example`, `Makefile`, `scripts/bootstrap.sh`
- `manifests/sample-app.yaml`, `manifests/sample-service.yaml`, `manifests/sample-ingress.yaml`
- `docs/architecture.md`, `docs/safety-checklist.md`

피해야 할 예:
- 스크립트, 매니페스트, 문서, 실험 로그를 모두 한 번에 커밋
- 의미 없는 메시지 예: `update`, `fix`, `changes`