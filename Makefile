# Makefile — CVE-2025-1974 IngressNightmare Lab (메타 래퍼)
# 실제 lab 코드는 ../cve-2025-1974-lab/ingressnightmare_project/ 에 위치
#
# 사용법:
#   make bootstrap    # 최초 환경 구성
#   make run          # collector + vulnerable admission 서버 동시 기동 (백그라운드)
#   make stop         # 기동한 서버 종료
#   make attack       # 공격 시뮬레이션 트래픽 전송
#   make benign       # 정상 트래픽 전송
#   make experiment   # 실험 실행 및 결과 저장
#   make clean        # 로그/결과 삭제
#   make help         # 이 도움말

PYTHON     ?= python3
LAB_ROOT   := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
REPO_DIR   := $(LAB_ROOT)/../cve-2025-1974-lab/ingressnightmare_project
VENV       := $(REPO_DIR)/.venv
VENV_PY    := $(VENV)/bin/python3
BOOTSTRAP  := $(LAB_ROOT)/scripts/bootstrap.sh

.PHONY: help bootstrap run stop attack benign experiment clean check

help:
	@echo ""
	@echo "CVE-2025-1974 IngressNightmare Lab — 사용 가능한 타겟:"
	@echo ""
	@echo "  make bootstrap    최초 환경 구성 (클론 + venv + 의존성)"
	@echo "  make run          collector + vulnerable 서버 백그라운드 기동"
	@echo "  make stop         백그라운드 서버 종료"
	@echo "  make attack       공격 시뮬레이션 트래픽"
	@echo "  make benign       정상 트래픽"
	@echo "  make experiment   실험 실행 (결과: $(REPO_DIR)/safe_lab/runtime/results/)"
	@echo "  make clean        로그/결과 초기화"
	@echo "  make check        환경 상태 점검"
	@echo ""

bootstrap:
	bash $(BOOTSTRAP)

check:
	@echo "[check] Python..."
	@$(PYTHON) --version
	@echo "[check] venv..."
	@test -f $(VENV_PY) && echo "  venv OK: $(VENV_PY)" || echo "  venv 없음 — make bootstrap 실행 필요"
	@echo "[check] 포트 18080 / 19090..."
	@ss -tlnp 2>/dev/null | grep -E '18080|19090' || echo "  서버 미실행 (정상)"

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
