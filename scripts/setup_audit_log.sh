#!/usr/bin/env bash
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

  echo "[Audit] audit-policy.yaml을 노드에 복사..."
  minikube cp "$POLICY_FILE" "/tmp/audit-policy.yaml" -p "$PROFILE"
  minikube ssh -p "$PROFILE" -- "sudo cp /tmp/audit-policy.yaml /etc/kubernetes/audit-policy.yaml"

  echo "[Audit] audit-log 디렉터리 생성..."
  minikube ssh -p "$PROFILE" -- "sudo mkdir -p /var/log/kubernetes && sudo chmod 755 /var/log/kubernetes"

  echo "[Audit] kube-apiserver 설정 패치..."

  cat > /tmp/patch_kube_apiserver_audit.py <<'PYEOF'
from pathlib import Path

manifest = Path("/etc/kubernetes/manifests/kube-apiserver.yaml")
text = manifest.read_text()

audit_flags = [
    "    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml",
    "    - --audit-log-path=/var/log/kubernetes/audit.log",
    "    - --audit-log-maxage=1",
    "    - --audit-log-maxsize=50",
    "    - --audit-log-maxbackup=1",
]
remove_prefixes = tuple(flag.strip()[2:].split("=")[0] for flag in audit_flags)

lines = []
for line in text.splitlines():
    stripped = line.strip()
    if stripped.startswith("- --audit-") and any(stripped[2:].startswith(p) for p in remove_prefixes):
        continue
    lines.append(line)

patched = "\n".join(lines) + "\n"
insert_after = "    - kube-apiserver\n"
if insert_after in patched:
    patched = patched.replace(insert_after, insert_after + "\n".join(audit_flags) + "\n", 1)
else:
    raise SystemExit("kube-apiserver command block not found")

if "name: audit-policy" not in patched:
    volume_mounts = """    - mountPath: /etc/kubernetes/audit-policy.yaml
      name: audit-policy
      readOnly: true
    - mountPath: /var/log/kubernetes
      name: audit-logs
      readOnly: false
"""
    patched = patched.replace("  hostNetwork: true\n", volume_mounts + "  hostNetwork: true\n", 1)

    volumes = """  - hostPath:
      path: /etc/kubernetes/audit-policy.yaml
      type: File
    name: audit-policy
  - hostPath:
      path: /var/log/kubernetes
      type: DirectoryOrCreate
    name: audit-logs
"""
    patched = patched.replace("status: {}\n", volumes + "status: {}\n", 1)

manifest.write_text(patched)
print("kube-apiserver manifest 업데이트 완료")
PYEOF

  minikube cp /tmp/patch_kube_apiserver_audit.py "/tmp/patch_kube_apiserver_audit.py" -p "$PROFILE"
  minikube ssh -p "$PROFILE" -- "sudo python3 /tmp/patch_kube_apiserver_audit.py"

  echo "[Audit] kube-apiserver 재시작 대기..."
  sleep 20

  kubectl wait --for=condition=Ready pod \
    -n kube-system -l component=kube-apiserver --timeout=90s || true

  echo "[Audit] 활성화 완료"
  echo "  로그 확인: make detect-audit-tail"
}

cmd_tail() {
  echo "[Audit] 최근 로그 (Ctrl+C로 종료)..."
  minikube ssh -p "$PROFILE" -- "sudo tail -f $AUDIT_LOG_PATH"
}

cmd_disable() {
  echo "[Audit] Audit Log 비활성화..."

  cat > /tmp/disable_kube_apiserver_audit.py <<'PYEOF'
import yaml

manifest = "/etc/kubernetes/manifests/kube-apiserver.yaml"

with open(manifest) as f:
    doc = yaml.safe_load(f)

container = doc["spec"]["containers"][0]
cmd = container["command"]

remove_prefixes = [
    "--audit-policy-file",
    "--audit-log-path",
    "--audit-log-maxage",
    "--audit-log-maxsize",
    "--audit-log-maxbackup",
]

cmd = [f for f in cmd if not any(f.startswith(p) for p in remove_prefixes)]
container["command"] = cmd

with open(manifest, "w") as f:
    yaml.dump(doc, f, default_flow_style=False)

print("audit log 비활성화 완료")
PYEOF

  minikube cp /tmp/disable_kube_apiserver_audit.py "/tmp/disable_kube_apiserver_audit.py" -p "$PROFILE"
  minikube ssh -p "$PROFILE" -- "sudo python3 /tmp/disable_kube_apiserver_audit.py"

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
