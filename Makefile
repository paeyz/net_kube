# Makefile — CVE-2025-1974 IngressNightmare Lab (메타 래퍼)
# 실제 lab 코드는 cve-2025-1974-lab/ingressnightmare_project/ 에 위치 (bootstrap.sh 클론 위치)
#
# [Stage 1 — Python mock 시뮬레이션]
#   make bootstrap    최초 환경 구성 (클론 + venv + 의존성)
#   make run          collector + vulnerable 서버 백그라운드 기동
#   make stop         서버 종료
#   make attack / benign / experiment
#
# [Stage 2 — Minikube + 취약 ingress-nginx]
#   make cluster-up       클러스터 시작 (이미 존재하면 재시작)
#   make cluster-down     클러스터 중지
#   make cluster-delete   클러스터 삭제 (데이터 포함)
#   make cluster-status   클러스터 및 ingress-nginx 상태 확인
#   make webhook-info     admission webhook 엔드포인트 정보 출력

PYTHON          ?= python3
LAB_ROOT        := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
REPO_DIR        := $(LAB_ROOT)/cve-2025-1974-lab/ingressnightmare_project
VENV            := $(REPO_DIR)/.venv
VENV_PY         := $(VENV)/bin/python3
BOOTSTRAP       := $(LAB_ROOT)/scripts/bootstrap.sh
BOOTSTRAP_S2    := $(LAB_ROOT)/scripts/bootstrap_stage2.sh
MINIKUBE_PROFILE := cve-2025-1974-lab
PATH            := $(HOME)/.local/bin:$(PATH)
export PATH

.PHONY: help bootstrap bootstrap-stage2 \
        run stop attack benign experiment clean check \
        cluster-up cluster-down cluster-delete cluster-status webhook-info \
        poc poc-step1 poc-step2 poc-step3 \
        attack-enum attack-token attack-lateral attack-chain attack-d2-trigger \
        docker-build attacker-deploy attacker-logs attacker-delete \
        defense-m1 defense-m1-restore defense-m2 defense-m2-remove \
        defense-m3 defense-m3-remove defense-m4 defense-restore \
        blue2-m4 blue2-m4-remove-broad-crb blue2-b1 blue2-m5 blue2-report blue2-clean \
        detect-setup detect-falco detect-falco-rules detect-falco-logs detect-falco-remove \
        detect-gatekeeper detect-gatekeeper-policy detect-gatekeeper-violations detect-gatekeeper-remove \
        detect-audit detect-audit-tail detect-audit-disable \
        detect-status

help:
	@echo ""
	@echo "CVE-2025-1974 IngressNightmare Lab"
	@echo ""
	@echo "── Stage 1 (Python mock) ──────────────────────────────"
	@echo "  make bootstrap      최초 환경 구성 (venv + 의존성)"
	@echo "  make run            collector + admission 서버 기동"
	@echo "  make stop           서버 종료"
	@echo "  make attack         공격 시뮬레이션 트래픽"
	@echo "  make benign         정상 트래픽"
	@echo "  make experiment     실험 결과 수집"
	@echo "  make clean          로그/결과 초기화"
	@echo ""
	@echo "── Stage 2 (Minikube + ingress-nginx v1.11.3) ─────────"
	@echo "  make bootstrap-stage2   도구 설치 + 클러스터 생성 (최초 1회)"
	@echo "  make cluster-up         클러스터 시작"
	@echo "  make cluster-down       클러스터 중지"
	@echo "  make cluster-delete     클러스터 삭제"
	@echo "  make cluster-status     클러스터 + webhook 상태"
	@echo "  make webhook-info       admission webhook 엔드포인트 상세"
	@echo ""
	@echo "── Stage 3 (PoC 재현) ─────────────────────────────────"
	@echo "  make poc            전체 PoC 실행 (Step 1→2→3)"
	@echo "  make poc-step1      Step 1: webhook 연결 확인"
	@echo "  make poc-step2      Step 2: configuration-snippet 차단 확인"
	@echo "  make poc-step3      Step 3: auth-snippet 우회 + 파일 탈취"
	@echo ""
	@echo "  make check          전체 환경 점검"
	@echo ""
	@echo "── Stage 4 (Red Team 공격 체인) ───────────────────────"
	@echo "  make attack-enum         시나리오 A: 파일 열거 + D2 탐지 트리거 포함"
	@echo "  make attack-token        시나리오 B: SA 토큰 추출"
	@echo "  make attack-lateral      시나리오 C: Lateral Movement"
	@echo "  make attack-chain        전체 T1→T4 자동화"
	@echo "  make attack-d2-trigger   D2 단독 트리거 (Gatekeeper/Audit Log 검증용)"
	@echo "  make docker-build     공격자 이미지 빌드 + minikube image load"
	@echo "  make attacker-deploy  공격자 파드 배포 (클러스터 내부 실행)"
	@echo "  make attacker-logs    공격자 파드 로그 확인"
	@echo "  make attacker-delete  공격자 파드 정리"
	@echo ""
	@echo "── Blue Team (방어 구현) ───────────────────────────────"
	@echo "  make defense-m1           M1: admission webhook 비활성화"
	@echo "  make defense-m1-restore   M1: webhook 복원"
	@echo "  make defense-m2           M2: NetworkPolicy 적용"
	@echo "  make defense-m2-remove    M2: NetworkPolicy 제거"
	@echo "  make defense-m3           M3: ValidatingAdmissionPolicy 적용"
	@echo "  make defense-m3-remove    M3: VAP 제거"
	@echo "  make defense-m4           M4: RBAC 최소 권한 적용"
	@echo "  make defense-restore      전체 방어 정책 제거 (원상복구)"
	@echo ""
	@echo "── Blue Team 2 (M4/B1/M5 자동 검증) ───────────────────"
	@echo "  make blue2-m4                    M4 RBAC 최소 권한화 검증"
	@echo "  make blue2-m4-remove-broad-crb   M4 검증 + broad CRB 백업/삭제 옵션"
	@echo "  make blue2-b1                    ingress-nginx v1.11.5 패치 검증"
	@echo "  make blue2-m5                    M2+M3+M4 통합 검증"
	@echo "  make blue2-report                Korean report draft 생성"
	@echo "  make blue2-clean                 Blue2 generated results 삭제"
	@echo ""
	@echo "── Detection Team (탐지 구현) ──────────────────────────"
	@echo "  make detect-setup             Falco + Gatekeeper + Audit Log 일괄 설치"
	@echo "  make detect-falco             Falco DaemonSet 설치"
	@echo "  make detect-falco-rules       커스텀 룰 적용 (D1/D3/D4)"
	@echo "  make detect-falco-logs        Falco 실시간 알림 확인"
	@echo "  make detect-falco-remove      Falco 제거"
	@echo "  make detect-gatekeeper        OPA/Gatekeeper 설치"
	@echo "  make detect-gatekeeper-policy D2 정책 적용 (warn 모드)"
	@echo "  make detect-gatekeeper-violations  violation 확인"
	@echo "  make detect-gatekeeper-remove OPA/Gatekeeper 제거"
	@echo "  make detect-audit             kube-apiserver Audit Log 활성화"
	@echo "  make detect-audit-tail        Audit Log 실시간 확인"
	@echo "  make detect-audit-disable     Audit Log 비활성화"
	@echo "  make detect-status            탐지 도구 전체 상태 확인"
	@echo ""

# ── Stage 1 ────────────────────────────────────────────────────────────────────
bootstrap:
	bash $(BOOTSTRAP)

check:
	@echo "=== Stage 1 ==="
	@$(PYTHON) --version
	@test -f $(VENV_PY) && echo "  venv OK: $(VENV_PY)" || echo "  venv 없음 — make bootstrap 실행 필요"
	@ss -tlnp 2>/dev/null | grep -E '18080|19090' || echo "  Python 서버 미실행"
	@echo ""
	@echo "=== Stage 2 ==="
	@minikube status -p $(MINIKUBE_PROFILE) 2>/dev/null || echo "  클러스터 없음 또는 중지됨"
	@kubectl get pods -n ingress-nginx 2>/dev/null || echo "  ingress-nginx 상태 조회 불가"

# 두 서버를 백그라운드로 동시 기동 (PID 파일로 관리)
run: _check_venv
	@echo "[run] Collector 서버 기동 (port 19090)..."
	@cd $(REPO_DIR) && \
	  $(VENV_PY) -m safe_lab.collector_server --port 19090 & echo $$! > /tmp/lab_collector.pid
	@sleep 1
	@echo "[run] Admission 서버 기동 (mode=vulnerable, port 18080)..."
	@cd $(REPO_DIR) && \
	  $(VENV_PY) -m safe_lab.admission_server --mode vulnerable --port 18080 \
	    --collector-url http://127.0.0.1:19090 & echo $$! > /tmp/lab_admission.pid
	@echo "[run] 기동 완료. 'make stop' 으로 종료."

stop:
	@for f in /tmp/lab_collector.pid /tmp/lab_admission.pid; do \
	  if [ -f $$f ]; then \
	    kill $$(cat $$f) 2>/dev/null && echo "[stop] PID $$(cat $$f) 종료" || true; \
	    rm -f $$f; \
	  fi; \
	done

attack: _check_venv
	cd $(REPO_DIR) && $(VENV_PY) -m safe_lab.attacks.attack_simulator attack \
	  --target http://127.0.0.1:18080 --collector http://127.0.0.1:19090

benign: _check_venv
	cd $(REPO_DIR) && $(VENV_PY) -m safe_lab.attacks.attack_simulator benign \
	  --target http://127.0.0.1:18080

experiment: _check_venv
	cd $(REPO_DIR) && $(VENV_PY) -m safe_lab.experiments.run_experiments \
	  --out-dir safe_lab/runtime/results

clean:
	cd $(REPO_DIR) && \
	  find safe_lab/runtime/logs   -type f ! -name '.gitkeep' -delete && \
	  find safe_lab/runtime/results -type f ! -name '.gitkeep' -delete
	@echo "[clean] 완료"

_check_venv:
	@test -f $(VENV_PY) || (echo "[ERROR] venv 없음. 먼저 'make bootstrap' 실행" && exit 1)

# ── Stage 2 ────────────────────────────────────────────────────────────────────
bootstrap-stage2:
	bash $(BOOTSTRAP_S2)

cluster-up:
	minikube start -p $(MINIKUBE_PROFILE) --wait all

cluster-down:
	minikube stop -p $(MINIKUBE_PROFILE)

cluster-delete:
	@echo "⚠  클러스터 전체 삭제: $(MINIKUBE_PROFILE)"
	@read -p "계속하려면 Enter, 취소하려면 Ctrl-C: " _
	minikube delete -p $(MINIKUBE_PROFILE)

cluster-status:
	@echo "=== Minikube ==="
	@minikube status -p $(MINIKUBE_PROFILE)
	@echo ""
	@echo "=== Nodes ==="
	@kubectl get nodes -o wide
	@echo ""
	@echo "=== ingress-nginx Pods ==="
	@kubectl get pods -n ingress-nginx -o wide
	@echo ""
	@echo "=== ValidatingWebhookConfiguration ==="
	@kubectl get validatingwebhookconfigurations

webhook-info:
	@echo "=== Admission Webhook 상세 ==="
	@kubectl get validatingwebhookconfigurations ingress-nginx-admission -o yaml
	@echo ""
	@echo "=== Controller Image ==="
	@kubectl get deploy ingress-nginx-controller -n ingress-nginx \
	  -o jsonpath='{.spec.template.spec.containers[0].image}' && echo ""
	@echo ""
	@echo "=== Webhook Service ==="
	@kubectl get svc ingress-nginx-controller-admission -n ingress-nginx

# ── Stage 3 ────────────────────────────────────────────────────────────────────
poc:
	bash $(LAB_ROOT)/scripts/stage3_run.sh all

poc-step1:
	bash $(LAB_ROOT)/scripts/stage3_run.sh 1

poc-step2:
	bash $(LAB_ROOT)/scripts/stage3_run.sh 2

poc-step3:
	bash $(LAB_ROOT)/scripts/stage3_run.sh 3

# ── Stage 4 (Red Team 공격 체인) ────────────────────────────────────────────────
ATTACK_TARGET  ?= https://127.0.0.1:8443
ATTACK_OUT     ?= $(LAB_ROOT)/results
ATTACKER_IMAGE ?= cve-2025-1974-attacker:latest
PF_PID_FILE    ?= /tmp/poc_portforward.pid
PF_LOG_FILE    ?= /tmp/poc_portforward.log
export PF_LOG_FILE PF_PID_FILE

# port-forward를 열고 attack_chain.py를 실행하는 내부 헬퍼
# ATTACK_STEP 변수로 단계 제어 (enum | token | lateral | all)
_attack-run:
	@if ! ss -tlnp 2>/dev/null | grep -q ':8443'; then \
	  echo "[INFO] port-forward 시작 (8443)..."; \
	  kubectl port-forward svc/ingress-nginx-controller-admission \
	    8443:443 -n ingress-nginx >$(PF_LOG_FILE) 2>&1 & \
	  echo $$! > $(PF_PID_FILE); \
	  sleep 2; \
	fi
	$(PYTHON) $(LAB_ROOT)/poc/attack_chain.py \
	  --target $(ATTACK_TARGET) \
	  --out $(ATTACK_OUT) \
	  --step $(ATTACK_STEP)
	@if [ -f $(PF_PID_FILE) ]; then \
	  kill $$(cat $(PF_PID_FILE)) 2>/dev/null || true; \
	  rm -f $(PF_PID_FILE); \
	fi

attack-enum:
	$(MAKE) _attack-run ATTACK_STEP=enum

attack-token:
	$(MAKE) _attack-run ATTACK_STEP=token

attack-lateral:
	$(MAKE) _attack-run ATTACK_STEP=lateral

attack-chain:
	$(MAKE) _attack-run ATTACK_STEP=all

# D2 탐지 트리거 단독 실행
# Gatekeeper warn/deny violation + Audit Log requestObject 확인용
# 사용: make attack-d2-trigger
#   → 확인: make detect-gatekeeper-violations
#   → 확인: make detect-audit-tail
attack-d2-trigger:
	$(PYTHON) -c "\
from poc.modules.file_enum import trigger_via_apiserver; \
r = trigger_via_apiserver(verbose=True); \
print(); \
print('[결과]', '성공' if r['triggered'] else '실패', '|', r['output'][:80])"

docker-build:
	docker build -t $(ATTACKER_IMAGE) $(LAB_ROOT)
	minikube image load $(ATTACKER_IMAGE) -p $(MINIKUBE_PROFILE)

attacker-deploy:
	kubectl apply -f $(LAB_ROOT)/k8s/attacker-pod.yaml

attacker-logs:
	kubectl logs -f attacker-pod -n default

attacker-delete:
	kubectl delete -f $(LAB_ROOT)/k8s/attacker-pod.yaml --ignore-not-found

# ── Blue Team (방어 구현) ────────────────────────────────────────────────────
defense-m1:
	bash $(LAB_ROOT)/defense/m1-webhook-disable.sh apply

defense-m1-restore:
	bash $(LAB_ROOT)/defense/m1-webhook-disable.sh restore

defense-m2:
	kubectl apply -f $(LAB_ROOT)/defense/m2-networkpolicy.yaml

defense-m2-remove:
	kubectl delete -f $(LAB_ROOT)/defense/m2-networkpolicy.yaml --ignore-not-found

defense-m3:
	kubectl apply -f $(LAB_ROOT)/defense/m3-vap.yaml

defense-m3-remove:
	kubectl delete -f $(LAB_ROOT)/defense/m3-vap.yaml --ignore-not-found

defense-m4:
	kubectl apply -f $(LAB_ROOT)/defense/m4-rbac-hardened.yaml

defense-restore:
	@echo "[restore] 방어 정책 전체 제거..."
	kubectl delete -f $(LAB_ROOT)/defense/m3-vap.yaml --ignore-not-found
	kubectl delete -f $(LAB_ROOT)/defense/m2-networkpolicy.yaml --ignore-not-found
	kubectl delete -f $(LAB_ROOT)/defense/m4-rbac-hardened.yaml --ignore-not-found
	@echo "[restore] 완료 — make cluster-status 로 상태 확인"

# ── Blue Team 2 (M4/B1/M5 자동 검증) ────────────────────────────────────────
blue2-m4:
	bash $(LAB_ROOT)/scripts/blue2/m4_rbac_validation.sh

blue2-m4-remove-broad-crb:
	bash $(LAB_ROOT)/scripts/blue2/m4_rbac_validation.sh --remove-broad-crb

blue2-b1:
	bash $(LAB_ROOT)/scripts/blue2/b1_patch_validation.sh

blue2-m5:
	bash $(LAB_ROOT)/scripts/blue2/m5_fullstack_validation.sh

blue2-report:
	$(PYTHON) $(LAB_ROOT)/scripts/blue2/generate_report.py

blue2-clean:
	@echo "⚠  Blue2 generated results will be removed: $(LAB_ROOT)/results/blue2"
	@read -p "Type 'yes' to continue: " ans; \
	if [ "$$ans" = "yes" ]; then \
	  rm -rf "$(LAB_ROOT)/results/blue2"; \
	  echo "[blue2-clean] removed $(LAB_ROOT)/results/blue2"; \
	else \
	  echo "[blue2-clean] cancelled"; \
	fi

# ── Detection Team (탐지 구현) ───────────────────────────────────────────────
detect-setup:
	@echo "[detect] Falco + Gatekeeper + Audit Log 일괄 설치..."
	bash $(LAB_ROOT)/scripts/setup_falco.sh install
	bash $(LAB_ROOT)/scripts/setup_gatekeeper.sh install
	bash $(LAB_ROOT)/scripts/setup_audit_log.sh enable
	@echo "[detect] 설치 완료 — make detect-status 로 확인"

detect-falco:
	bash $(LAB_ROOT)/scripts/setup_falco.sh install

detect-falco-rules:
	bash $(LAB_ROOT)/scripts/setup_falco.sh rules

detect-falco-logs:
	bash $(LAB_ROOT)/scripts/setup_falco.sh logs

detect-falco-remove:
	bash $(LAB_ROOT)/scripts/setup_falco.sh uninstall

detect-gatekeeper:
	bash $(LAB_ROOT)/scripts/setup_gatekeeper.sh install

detect-gatekeeper-policy:
	bash $(LAB_ROOT)/scripts/setup_gatekeeper.sh policy

detect-gatekeeper-violations:
	bash $(LAB_ROOT)/scripts/setup_gatekeeper.sh violations

detect-gatekeeper-remove:
	bash $(LAB_ROOT)/scripts/setup_gatekeeper.sh uninstall

detect-audit:
	bash $(LAB_ROOT)/scripts/setup_audit_log.sh enable

detect-audit-tail:
	bash $(LAB_ROOT)/scripts/setup_audit_log.sh tail

detect-audit-disable:
	bash $(LAB_ROOT)/scripts/setup_audit_log.sh disable

detect-status:
	@echo "=== Falco ==="
	@kubectl get pods -n falco -o wide 2>/dev/null || echo "  (미설치)"
	@echo ""
	@echo "=== OPA/Gatekeeper ==="
	@kubectl get pods -n gatekeeper-system -o wide 2>/dev/null || echo "  (미설치)"
	@echo ""
	@echo "=== Gatekeeper Violations ==="
	@kubectl get blocknginxdangerousannotations -A 2>/dev/null || echo "  (Constraint 없음)"
	@echo ""
	@echo "=== Defense Policies ==="
	@kubectl get networkpolicy -n ingress-nginx 2>/dev/null || echo "  (NetworkPolicy 없음)"
	@kubectl get validatingadmissionpolicy 2>/dev/null || echo "  (VAP 없음)"
