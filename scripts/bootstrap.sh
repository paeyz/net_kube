#!/usr/bin/env bash
# bootstrap.sh — CVE-2025-1974 IngressNightmare Lab 환경 자동 구성 (Linux/WSL2/macOS)
# 사용법: bash scripts/bootstrap.sh [--lab-dir <경로>]
#
# 동작 순서:
#   1) Python 3.11+ 확인
#   2) 대상 프로젝트 클론 (미존재 시)
#   3) venv 생성 및 의존성 설치
#   4) 동작 확인
set -euo pipefail

# ── 설정 ──────────────────────────────────────────────────────────────────────
REPO_URL="https://github.com/zsxen/cve-2025-1974-lab.git"
# 고정 커밋 — 재현성 보장 (master HEAD 기준 2025-04-09)
REPO_REF="master"
LAB_SUBDIR="ingressnightmare_project"
# 기본 클론 위치: 이 스크립트가 있는 저장소 옆 디렉터리
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_LAB_DIR="$(dirname "$SCRIPT_DIR")/cve-2025-1974-lab/$LAB_SUBDIR"
LAB_DIR="${1:-$DEFAULT_LAB_DIR}"
MIN_PYTHON_MINOR=11

# ── 색상 출력 ─────────────────────────────────────────────────────────────────
_info()  { echo "[INFO]  $*"; }
_ok()    { echo "[OK]    $*"; }
_warn()  { echo "[WARN]  $*"; }
_die()   { echo "[ERROR] $*" >&2; exit 1; }

# ── 1. Python 버전 확인 ───────────────────────────────────────────────────────
_info "Python 3.11+ 확인 중..."
PYTHON_BIN=""
for bin in python3.11 python3.12 python3.13 python3; do
    if command -v "$bin" >/dev/null 2>&1; then
        ver=$("$bin" -c 'import sys; print(sys.version_info.minor)')
        major=$("$bin" -c 'import sys; print(sys.version_info.major)')
        if [[ "$major" -eq 3 && "$ver" -ge "$MIN_PYTHON_MINOR" ]]; then
            PYTHON_BIN="$bin"
            break
        fi
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    _warn "Python 3.11+ 를 찾지 못했습니다."
    _warn "Ubuntu/Debian: sudo apt install -y python3.11 python3.11-venv"
    _warn "macOS:         brew install python@3.11"
    _die  "Python 3.11+ 설치 후 다시 실행하세요."
fi
_ok "사용할 Python: $PYTHON_BIN ($($PYTHON_BIN --version))"

# ── 2. 저장소 클론 ────────────────────────────────────────────────────────────
REPO_ROOT="$(dirname "$(dirname "$DEFAULT_LAB_DIR")")/cve-2025-1974-lab"
if [[ ! -d "$REPO_ROOT/.git" ]]; then
    _info "저장소 클론: $REPO_URL → $REPO_ROOT"
    git clone --branch "$REPO_REF" --depth 1 "$REPO_URL" "$REPO_ROOT"
else
    _ok "저장소 이미 존재: $REPO_ROOT (클론 생략)"
fi

LAB_DIR="$REPO_ROOT/$LAB_SUBDIR"
if [[ ! -d "$LAB_DIR" ]]; then
    _die "서브디렉터리 없음: $LAB_DIR"
fi
_ok "작업 디렉터리: $LAB_DIR"
cd "$LAB_DIR"

# ── 3. venv 생성 & 의존성 설치 ───────────────────────────────────────────────
VENV_DIR="$LAB_DIR/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
    _info "venv 생성: $VENV_DIR"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
else
    _ok "venv 이미 존재 (재사용)"
fi

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"
_info "pip 업그레이드..."
pip install --quiet --upgrade pip

_info "의존성 설치: requirements.txt"
pip install --quiet -r requirements.txt

# ── 4. 동작 확인 ──────────────────────────────────────────────────────────────
_info "import 확인..."
python3 -c "import requests, psutil; print('[OK]    requests & psutil import 성공')"

_info "collector_server 모듈 확인..."
python3 -c "from safe_lab import collector_server; print('[OK]    collector_server 모듈 로드 성공')"

_info "admission_server 모듈 확인..."
python3 -c "from safe_lab import admission_server; print('[OK]    admission_server 모듈 로드 성공')"

# ── 완료 ──────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  부트스트랩 완료!"
echo "  작업 디렉터리: $LAB_DIR"
echo ""
echo "  다음 단계:"
echo "    cd $LAB_DIR"
echo "    source .venv/bin/activate"
echo ""
echo "  [터미널 1]  make run-collector"
echo "  [터미널 2]  make run-vulnerable   # 또는 run-patched / run-apiserver-only"
echo "  [터미널 3]  make attack           # 또는 benign / experiment"
echo ""
echo "  상세 안내: SETUP.md / TROUBLESHOOTING.md 참고"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
