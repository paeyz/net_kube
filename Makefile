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
        cluster-up cluster-down cluster-delete cluster-status webhook-info

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
	@echo "── Stage 2 (Minikube + ingress-nginx v1.11.4) ─────────"
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
