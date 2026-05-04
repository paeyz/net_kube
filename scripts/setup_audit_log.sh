#!/usr/bin/env bash
# Detection Team — Kubernetes Audit Log 활성화 (Minikube)
#
# 사용법: bash scripts/setup_audit_log.sh [enable|tail|disable]
#
# 원리:
#   Minikube의 kube-apiserver에 --audit-log-path, --audit-policy-file 플래그를 추가.
#   Minikube는 control-plane 노드의 /etc/kubernetes/addons/ 에 파일을 마운트할 수 있다.
#
# 참고: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/

set -euo pipefail

PROFILE="${MINIKUBE_PROFILE:-cve-2025-1974-lab}"
POLICY_FILE="$(dirname "$0")/../monitoring/audit-policy.yaml"
AUDIT_LOG_PATH="/var/log/kubernetes/audit.log"

cmd_enable() {
  echo "[Audit] Minikube에 Audit Log 활성화..."

  if [ ! -f "$POLICY_FILE" ]; then
    echo "[ERROR] $POLICY_FILE 이 없습니다"
    exit 1
  fi

  # policy 파일을 Minikube 노드에 복사
  echo "[Audit] audit-policy.yaml을 노드에 복사..."
  minikube cp "$POLICY_FILE" /etc/kubernetes/audit-policy.yaml -p "$PROFILE"

  # apiserver 패치 (kube-apiserver static pod 수정)
  echo "[Audit] kube-apiserver 설정 패치..."
  minikube ssh -p "$PROFILE" -- sudo sh -c '
    # audit-log 디렉터리 생성
    mkdir -p /var/log/kubernetes

    # kube-apiserver manifest 수정 (Python으로 파싱)
    MANIFEST=/etc/kubernetes/manifests/kube-apiserver.yaml
    python3 - << '"'"'PYEOF'"'"'
import yaml, sys

with open("/etc/kubernetes/manifests/kube-apiserver.yaml") as f:
    doc = yaml.safe_load(f)

container = doc["spec"]["containers"][0]
cmd = container["command"]

flags_to_add = [
    "--audit-policy-file=/etc/kubernetes/audit-policy.yaml",
    "--audit-log-path=/var/log/kubernetes/audit.log",
    "--audit-log-maxage=1",
    "--audit-log-maxsize=50",
    "--audit-log-maxbackup=1",
]

# 이미 있는 플래그 제거 후 추가 (중복 방지)
cmd = [f for f in cmd if not any(f.startswith(flag.split("=")[0]) for flag in flags_to_add)]
cmd.extend(flags_to_add)
container["command"] = cmd

# volumeMounts 추가
vm = container.get("volumeMounts", [])
if not any(v["name"] == "audit-policy" for v in vm):
    vm.append({"name": "audit-policy", "mountPath": "/etc/kubernetes/audit-policy.yaml", "readOnly": True})
if not any(v["name"] == "audit-logs" for v in vm):
    vm.append({"name": "audit-logs", "mountPath": "/var/log/kubernetes", "readOnly": False})
container["volumeMounts"] = vm

# volumes 추가
vols = doc["spec"].get("volumes", [])
if not any(v["name"] == "audit-policy" for v in vols):
    vols.append({"name": "audit-policy", "hostPath": {"path": "/etc/kubernetes/audit-policy.yaml", "type": "File"}})
if not any(v["name"] == "audit-logs" for v in vols):
    vols.append({"name": "audit-logs", "hostPath": {"path": "/var/log/kubernetes", "type": "DirectoryOrCreate"}})
doc["spec"]["volumes"] = vols

with open("/etc/kubernetes/manifests/kube-apiserver.yaml", "w") as f:
    yaml.dump(doc, f, default_flow_style=False)

print("kube-apiserver manifest 업데이트 완료")
PYEOF
  '

  echo "[Audit] kube-apiserver 재시작 대기 (최대 60초)..."
  sleep 10
  kubectl wait --for=condition=Ready pod/kube-apiserver-minikube \
    -n kube-system --timeout=60s 2>/dev/null || \
  kubectl wait --for=condition=Ready pod \
    -n kube-system -l component=kube-apiserver --timeout=60s

  echo "[Audit] 활성화 완료"
  echo "  로그 확인: make detect-audit-tail"
}

cmd_tail() {
  echo "[Audit] 최근 로그 (Ctrl+C로 종료)..."
  minikube ssh -p "$PROFILE" -- sudo tail -f "$AUDIT_LOG_PATH" 2>/dev/null | \
    python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        ev = json.loads(line)
        verb = ev.get('verb','')
        user = ev.get('user',{}).get('username','')
        res  = ev.get('objectRef',{}).get('resource','')
        ns   = ev.get('objectRef',{}).get('namespace','')
        name = ev.get('objectRef',{}).get('name','')
        src  = ','.join(ev.get('sourceIPs',[]))
        print(f'  [{verb:8}] {user:50} {res}/{ns}/{name} src={src}')
    except Exception:
        print(f'  {line[:120]}')
" 2>/dev/null || minikube ssh -p "$PROFILE" -- sudo tail -f "$AUDIT_LOG_PATH"
}

cmd_disable() {
  echo "[Audit] Audit Log 비활성화..."
  minikube ssh -p "$PROFILE" -- sudo python3 - << 'PYEOF'
import yaml

with open("/etc/kubernetes/manifests/kube-apiserver.yaml") as f:
    doc = yaml.safe_load(f)

container = doc["spec"]["containers"][0]
cmd = container["command"]
remove_prefixes = ["--audit-policy-file", "--audit-log-path", "--audit-log-maxage",
                   "--audit-log-maxsize", "--audit-log-maxbackup"]
cmd = [f for f in cmd if not any(f.startswith(p) for p in remove_prefixes)]
container["command"] = cmd

with open("/etc/kubernetes/manifests/kube-apiserver.yaml", "w") as f:
    yaml.dump(doc, f, default_flow_style=False)
print("audit log 비활성화 완료")
PYEOF
  echo "[Audit] 비활성화 완료"
}

case "${1:-enable}" in
  enable)  cmd_enable ;;
  tail)    cmd_tail ;;
  disable) cmd_disable ;;
  *)
    echo "사용법: $0 [enable|tail|disable]"
    exit 1
    ;;
esac
