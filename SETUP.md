# SETUP — CVE-2025-1974 IngressNightmare Local Lab

> **목적**: [zsxen/cve-2025-1974-lab](https://github.com/zsxen/cve-2025-1974-lab/tree/master/ingressnightmare_project)
> 프로젝트를 로컬에서 재현 가능하게 실행하기 위한 가이드.
>
> **안전 원칙**: 모든 트래픽은 `127.0.0.1` 루프백으로 한정. Kubernetes 불필요. 실제 exploit/무기화 코드 없음.

---

## 1. 요구사항 체크리스트

| 항목 | 최소 버전 | 확인 명령 |
|------|-----------|-----------|
| Python | 3.11+ | `python3 --version` |
| pip | 23+ | `pip --version` |
| git | 2.x | `git --version` |
| tcpdump (선택) | any | `tcpdump --version` |
| Wireshark (선택) | any | GUI 설치 |

**Kubernetes / Docker / Minikube 는 이 프로젝트에서 필요 없음.**

---

## 2. 환경별 선택 가이드

### 권장 경로

| 환경 | 경로 |
|------|------|
| macOS / Ubuntu / Debian | [섹션 3 — 네이티브 Linux/macOS](#3-네이티브-linuxmacos) |
| **Windows (권장)** | [섹션 4 — WSL2](#4-windows--wsl2) |
| Windows (WSL2 없는 경우) | [섹션 5 — PowerShell 네이티브](#5-windows-powershell-네이티브) |

> **왜 WSL2를 권장하나?**
> `pcap_capture.sh`(tcpdump)와 `make` 타겟이 POSIX 쉘 기반이라
> WSL2에서 그대로 실행된다. PowerShell 네이티브는 스크립트를 별도로 변환해야 한다.

---

## 3. 네이티브 Linux/macOS

```bash
# 1) 이 저장소 클론 (아직 안 했다면)
git clone https://github.com/zsxen/cve-2025-1974-lab.git
cd cve-2025-1974-lab/ingressnightmare_project

# 2) Python 버전 확인
python3 --version   # 3.11.x 이상이어야 함

# 3) 가상환경 생성 & 활성화
python3 -m venv .venv
source .venv/bin/activate

# 4) 의존성 설치 (버전 고정)
pip install --upgrade pip
pip install -r requirements.txt

# 5) 설치 확인
python3 -c "import requests, psutil; print('OK')"
```

---

## 4. Windows + WSL2

### 4-1. WSL2 설치 (최초 1회)

PowerShell (관리자) 에서:

```powershell
wsl --install -d Ubuntu-22.04
# 재부팅 후 Ubuntu 사용자명/비밀번호 설정
```

### 4-2. Ubuntu 안에서 Python 3.11 준비

```bash
sudo apt update && sudo apt install -y python3.11 python3.11-venv python3-pip git make
python3.11 --version   # 3.11.x
```

### 4-3. 프로젝트 클론 & 가상환경

```bash
# WSL2 홈 디렉터리에서 작업 (Windows 드라이브 /mnt/c/... 보다 빠름)
cd ~
git clone https://github.com/zsxen/cve-2025-1974-lab.git
cd cve-2025-1974-lab/ingressnightmare_project

python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python3 -c "import requests, psutil; print('OK')"
```

### 4-4. Windows 측 파일 접근 (선택)

Windows 경로 `/mnt/c/net_kube` 에서 작업할 경우:

```bash
# 성능 저하 없이 접근 가능하나, I/O 집약 작업은 WSL2 홈을 권장
cd /mnt/c/net_kube
```

---

## 5. Windows PowerShell 네이티브

> make 타겟이 bash 기반이므로, PowerShell에서는 `scripts/bootstrap.ps1`을 사용한다.

```powershell
# Python 3.11 설치: https://www.python.org/downloads/
# 설치 후 확인
python --version   # 3.11.x

# 프로젝트 클론
git clone https://github.com/zsxen/cve-2025-1974-lab.git
cd cve-2025-1974-lab\ingressnightmare_project

# 가상환경
python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r requirements.txt
python -c "import requests, psutil; print('OK')"
```

> PowerShell에서 `pcap_capture.sh`는 사용 불가. Wireshark를 직접 열어 `lo` 인터페이스를 캡처하거나 WSL2를 사용한다.

---

## 6. 실행 순서 (공통)

터미널 두 개를 열어 각각 실행한다.

### 터미널 1 — Collector 서버 시작

```bash
source .venv/bin/activate
make run-collector
# 또는: python3 -m safe_lab.collector_server --port 19090
```

`Collector listening on 0.0.0.0:19090` 메시지 확인 후 다음 단계 진행.

### 터미널 2 — Admission 서버 시작 (3가지 모드 중 선택)

```bash
source .venv/bin/activate

# 취약 모드 (기본 실습용)
make run-vulnerable
# 패치 모드 (방어 확인용)
make run-patched
# API-server-only 모드 (네트워크 정책 실습용)
make run-apiserver-only
```

### 터미널 3 (또는 동일 세션) — 트래픽 생성

```bash
source .venv/bin/activate

make attack    # 공격 시뮬레이션 트래픽
make benign    # 정상 트래픽
make experiment  # 결과 수집
```

결과물은 `safe_lab/runtime/results/` 에 저장됨.

---

## 7. 패킷 캡처 (선택)

```bash
# Linux/WSL2: tcpdump 설치
sudo apt install -y tcpdump

# 캡처 실행 (백그라운드)
bash pcap_capture.sh &

# 중지
kill %1
```

Wireshark 필터는 `wireshark_filters.txt` 참고.

---

## 8. 초기화 (Clean-up)

```bash
make clean   # 로그/결과 파일 삭제 (.gitkeep 유지)
deactivate   # 가상환경 종료
```

---

## 9. 자동 부트스트랩 (스크립트 경로)

| 환경 | 스크립트 |
|------|---------|
| Linux / WSL2 | `scripts/bootstrap.sh` |
| Windows PowerShell | `scripts/bootstrap.ps1` |

각 스크립트는 Python 버전 확인 → venv 생성 → 의존성 설치 → 동작 확인까지 자동으로 수행한다.

```bash
# Linux/WSL2
bash scripts/bootstrap.sh

# Windows PowerShell
.\scripts\bootstrap.ps1
```
