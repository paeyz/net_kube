# bootstrap.ps1 — CVE-2025-1974 IngressNightmare Lab 환경 자동 구성 (Windows PowerShell)
# 사용법: .\scripts\bootstrap.ps1
#
# 전제: Python 3.11+ 설치됨 (https://www.python.org/downloads/)
# 주의: make 타겟은 POSIX 전용 — PowerShell에서는 직접 명령을 사용하거나 WSL2를 권장

#Requires -Version 5.1
$ErrorActionPreference = "Stop"

# ── 설정 ──────────────────────────────────────────────────────────────────────
$RepoUrl    = "https://github.com/zsxen/cve-2025-1974-lab.git"
$RepoRef    = "master"
$LabSubDir  = "ingressnightmare_project"
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Join-Path (Split-Path -Parent $ScriptDir) "cve-2025-1974-lab"
$LabDir     = Join-Path $RepoRoot $LabSubDir

function Write-Info  { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

# ── 실행 정책 확인 ────────────────────────────────────────────────────────────
$policy = Get-ExecutionPolicy -Scope CurrentUser
if ($policy -eq "Restricted") {
    Write-Warn "실행 정책이 Restricted입니다. 변경합니다..."
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    Write-Ok "실행 정책 변경 완료"
}

# ── 1. Python 3.11+ 확인 ───────────────────────────────────────────────────────
Write-Info "Python 3.11+ 확인 중..."
$pythonBin = $null
foreach ($bin in @("python3.11", "python3.12", "python3", "python")) {
    try {
        $ver = & $bin -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        if ($ver -match "^3\.(\d+)$" -and [int]$Matches[1] -ge 11) {
            $pythonBin = $bin
            Write-Ok "사용할 Python: $bin ($ver)"
            break
        }
    } catch { }
}
if (-not $pythonBin) {
    Write-Warn "Python 3.11+ 를 찾지 못했습니다."
    Write-Warn "다운로드: https://www.python.org/downloads/release/python-3119/"
    Write-Warn "또는 WSL2 사용: wsl --install -d Ubuntu-22.04"
    Write-Fail "Python 3.11+ 설치 후 다시 실행하세요."
}

# ── 2. 저장소 클론 ────────────────────────────────────────────────────────────
if (-not (Test-Path (Join-Path $RepoRoot ".git"))) {
    Write-Info "저장소 클론: $RepoUrl → $RepoRoot"
    git clone --branch $RepoRef --depth 1 $RepoUrl $RepoRoot
} else {
    Write-Ok "저장소 이미 존재: $RepoRoot (클론 생략)"
}

if (-not (Test-Path $LabDir)) {
    Write-Fail "서브디렉터리 없음: $LabDir"
}
Write-Ok "작업 디렉터리: $LabDir"
Set-Location $LabDir

# ── 3. venv 생성 & 의존성 설치 ───────────────────────────────────────────────
$VenvDir = Join-Path $LabDir ".venv"
if (-not (Test-Path $VenvDir)) {
    Write-Info "venv 생성: $VenvDir"
    & $pythonBin -m venv $VenvDir
} else {
    Write-Ok "venv 이미 존재 (재사용)"
}

$activateScript = Join-Path $VenvDir "Scripts\Activate.ps1"
. $activateScript

Write-Info "pip 업그레이드..."
pip install --quiet --upgrade pip

Write-Info "의존성 설치: requirements.txt"
pip install --quiet -r requirements.txt

# ── 4. 동작 확인 ──────────────────────────────────────────────────────────────
Write-Info "import 확인..."
python -c "import requests, psutil; print('[OK]    requests & psutil import 성공')"

Write-Info "모듈 로드 확인..."
python -c "from safe_lab import collector_server, admission_server; print('[OK]    safe_lab 모듈 로드 성공')"

# ── 완료 ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  부트스트랩 완료!" -ForegroundColor Green
Write-Host "  작업 디렉터리: $LabDir"
Write-Host ""
Write-Host "  다음 단계 (PowerShell — 터미널 2개 열기):"
Write-Host ""
Write-Host "  [터미널 1]"
Write-Host "    cd $LabDir"
Write-Host "    .\.venv\Scripts\Activate.ps1"
Write-Host "    python -m safe_lab.collector_server --port 19090"
Write-Host ""
Write-Host "  [터미널 2]"
Write-Host "    cd $LabDir"
Write-Host "    .\.venv\Scripts\Activate.ps1"
Write-Host "    python -m safe_lab.admission_server --mode vulnerable --port 18080 --collector-url http://127.0.0.1:19090"
Write-Host ""
Write-Host "  [터미널 3 — 트래픽]"
Write-Host "    python -m safe_lab.attacks.attack_simulator attack --target http://127.0.0.1:18080 --collector http://127.0.0.1:19090"
Write-Host ""
Write-Host "  상세 안내: SETUP.md / TROUBLESHOOTING.md 참고"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
