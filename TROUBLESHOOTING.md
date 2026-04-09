# TROUBLESHOOTING — CVE-2025-1974 IngressNightmare Local Lab

자주 발생하는 문제와 해결 방법을 모아 둔 문서.

---

## T-01. `python3 --version` 이 3.9/3.10을 반환

**증상**: `python3 --version` → `3.9.x` 또는 `3.10.x`

**원인**: 시스템 기본 Python이 3.11 미만.

**해결**

```bash
# Ubuntu/Debian
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install -y python3.11 python3.11-venv

# 명시적으로 3.11 사용
python3.11 -m venv .venv

# macOS (Homebrew)
brew install python@3.11
python3.11 -m venv .venv
```

---

## T-02. `pip install` 중 `error: externally-managed-environment`

**증상**: Ubuntu 22.04+ 에서 `pip install` 시 PEP 668 오류.

**원인**: 시스템 Python에 직접 설치 시도. 반드시 venv 안에서 실행해야 함.

**해결**

```bash
python3 -m venv .venv
source .venv/bin/activate   # 활성화 확인: 프롬프트 앞에 (.venv) 표시
pip install -r requirements.txt
```

---

## T-03. `Address already in use` — 포트 18080 / 19090

**증상**: 서버 시작 시 `OSError: [Errno 98] Address already in use`

**원인**: 이전 실행이 남아 있거나 다른 프로세스가 해당 포트 사용 중.

**해결**

```bash
# 점유 프로세스 확인
sudo ss -tlnp | grep -E '18080|19090'
# 또는
lsof -i :18080
lsof -i :19090

# 강제 종료 (PID 확인 후)
kill <PID>

# 재시도
make run-collector
```

---

## T-04. `ModuleNotFoundError: No module named 'safe_lab'`

**증상**: `python3 -m safe_lab.xxx` 실행 시 모듈 없음 오류.

**원인**: 작업 디렉터리가 `ingressnightmare_project` 가 아니거나 venv가 비활성화됨.

**해결**

```bash
# 1) 디렉터리 확인
pwd  # 반드시 .../cve-2025-1974-lab/ingressnightmare_project 이어야 함

# 2) venv 활성화 확인
source .venv/bin/activate
which python3  # .venv/bin/python3 이어야 함

# 3) 재실행
make run-collector
```

---

## T-05. Windows PowerShell — `Activate.ps1` 실행 정책 오류

**증상**: `.\.venv\Scripts\Activate.ps1 : ... cannot be loaded because running scripts is disabled`

**원인**: PowerShell 실행 정책이 `Restricted`.

**해결** (현재 세션만):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\.venv\Scripts\Activate.ps1
```

---

## T-06. WSL2 — `/mnt/c/` 경로에서 Python I/O 느림

**증상**: venv 생성, pip install 이 비정상적으로 느림.

**원인**: WSL2 에서 Windows NTFS 경로(`/mnt/c/...`)는 9P 프로토콜을 거쳐 I/O가 느림.

**해결**: WSL2 홈 디렉터리(`~/`)에서 작업.

```bash
cd ~
git clone https://github.com/zsxen/cve-2025-1974-lab.git
cd cve-2025-1974-lab/ingressnightmare_project
python3.11 -m venv .venv
```

---

## T-07. `pcap_capture.sh` — `tcpdump: Operation not permitted`

**증상**: `sudo` 없이 tcpdump 실행 시 권한 오류.

**원인**: 패킷 캡처에 root 또는 `CAP_NET_RAW` 권한 필요.

**해결**

```bash
# sudo로 실행
sudo bash pcap_capture.sh

# 또는 tcpdump에 cap 부여 (영구)
sudo setcap cap_net_raw+ep $(which tcpdump)
bash pcap_capture.sh
```

WSL2에서는 `setcap`이 동작하지 않을 수 있으므로 `sudo` 사용 권장.

---

## T-08. `make: command not found` (Windows PowerShell)

**증상**: `make` 명령을 찾지 못함.

**원인**: Windows 기본 환경에는 `make` 미포함.

**해결 옵션**

1. **WSL2 사용** (권장) — `sudo apt install -y make`
2. **Chocolatey**: `choco install make`
3. **수동 실행**: `make` 대신 `scripts/bootstrap.ps1` 또는 아래 직접 명령 사용

```powershell
# make run-collector 대신
python -m safe_lab.collector_server --port 19090

# make run-vulnerable 대신
python -m safe_lab.admission_server --mode vulnerable --port 18080 --collector-url http://127.0.0.1:19090
```

---

## T-09. `requests` / `psutil` import 오류 — 버전 충돌

**증상**: `ImportError` 또는 의존성 충돌 메시지.

**해결**: venv를 삭제하고 재생성.

```bash
deactivate
rm -rf .venv
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## T-10. `make experiment` 후 결과 파일이 비어 있음

**증상**: `safe_lab/runtime/results/` 아래 파일이 생성되지 않거나 비어 있음.

**원인**: collector와 admission 서버가 모두 실행 중이어야 함.

**체크리스트**:
- [ ] 터미널 1에서 `make run-collector` 실행 중 (`Collector listening...` 확인)
- [ ] 터미널 2에서 `make run-vulnerable` (또는 다른 모드) 실행 중
- [ ] 그 후 `make experiment` 실행

---

## 추가 도움

문제가 해결되지 않는 경우:

1. `safe_lab/runtime/logs/` 의 로그 파일 확인
2. 프로세스 상태 확인: `ps aux | grep safe_lab`
3. 네트워크 상태: `ss -tlnp | grep -E '18080|19090'`
