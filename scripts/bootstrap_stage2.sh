#!/usr/bin/env bash
# bootstrap_stage2.sh — CVE-2025-1974 Stage 2: Minikube + 취약 ingress-nginx 환경 구축
#
# 전제조건:
#   - WSL2 Ubuntu (또는 Linux)
#   - Docker 실행 중, 현재 사용자가 docker 그룹 소속
#   - 인터넷 연결
#
# 설치 항목 (버전 고정):
#   kubectl    v1.30.8
#   minikube   v1.34.0
#   helm       v3.16.4
#
# Kubernetes 클러스터:
#   profile    cve-2025-1974-lab
#   k8s 버전   v1.30.8
#   driver     docker
#
# ingress-nginx (취약 버전):
#   chart      ingress-nginx/ingress-nginx
#   version    4.11.4  (controller image 1.11.4 — CVE-2025-1974 취약)
#   namespace  ingress-nginx

set -euo pipefail

# ── 버전 고정 ─────────────────────────────────────────────────────────────────
KUBECTL_VERSION="v1.30.8"
MINIKUBE_VERSION="v1.34.0"
HELM_VERSION="v3.16.4"
K8S_VERSION="v1.30.8"
MINIKUBE_PROFILE="cve-2025-1974-lab"
MINIKUBE_CPUS="2"
MINIKUBE_MEMORY="4096"
INGRESS_CHART_VERSION="4.11.3"        # controller=1.11.3, 취약 버전 (SHA 고정)
INGRESS_CONTROLLER_VERSION="v1.11.3"
INGRESS_DIGEST="sha256:d56f135b6462cfc476447cfe564b83a45e8bb7da2774963b00d12161112270b7"

BIN_DIR="$HOME/.local/bin"
ARCH="$(uname -m)"
[[ "$ARCH" == "x86_64" ]] && ARCH_SHORT="amd64" || ARCH_SHORT="arm64"

_info() { echo "[INFO]  $*"; }
_ok()   { echo "[OK]    $*"; }
_warn() { echo "[WARN]  $*"; }
_die()  { echo "[ERROR] $*" >&2; exit 1; }

mkdir -p "$BIN_DIR"
# PATH에 없으면 추가
echo "$PATH" | grep -q "$BIN_DIR" || export PATH="$BIN_DIR:$PATH"

# ── 1. Docker 접근 확인 ───────────────────────────────────────────────────────
_info "Docker 접근 확인..."
docker info >/dev/null 2>&1 || _die "Docker에 접근할 수 없습니다. 'sudo usermod -aG docker \$USER' 후 재로그인."
_ok "Docker OK"

# ── 2. kubectl 설치 ───────────────────────────────────────────────────────────
if command -v kubectl >/dev/null 2>&1 && kubectl version --client --short 2>/dev/null | grep -q "${KUBECTL_VERSION#v}"; then
    _ok "kubectl ${KUBECTL_VERSION} 이미 설치됨"
else
    _info "kubectl ${KUBECTL_VERSION} 설치 중..."
    curl -fsSLo "$BIN_DIR/kubectl" \
        "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH_SHORT}/kubectl"
    chmod +x "$BIN_DIR/kubectl"
    _ok "kubectl 설치 완료: $(kubectl version --client --short 2>/dev/null || kubectl version --client)"
fi

# ── 3. minikube 설치 ──────────────────────────────────────────────────────────
if command -v minikube >/dev/null 2>&1 && minikube version 2>/dev/null | grep -q "${MINIKUBE_VERSION#v}"; then
    _ok "minikube ${MINIKUBE_VERSION} 이미 설치됨"
else
    _info "minikube ${MINIKUBE_VERSION} 설치 중..."
    curl -fsSLo "$BIN_DIR/minikube" \
        "https://github.com/kubernetes/minikube/releases/download/${MINIKUBE_VERSION}/minikube-linux-${ARCH_SHORT}"
    chmod +x "$BIN_DIR/minikube"
    _ok "minikube 설치 완료: $(minikube version --short)"
fi

# ── 4. helm 설치 ─────────────────────────────────────────────────────────────
if command -v helm >/dev/null 2>&1 && helm version --short 2>/dev/null | grep -q "${HELM_VERSION#v}"; then
    _ok "helm ${HELM_VERSION} 이미 설치됨"
else
    _info "helm ${HELM_VERSION} 설치 중..."
    HELM_TMP=$(mktemp -d)
    curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-${ARCH_SHORT}.tar.gz" \
        | tar -xz -C "$HELM_TMP"
    cp "$HELM_TMP/linux-${ARCH_SHORT}/helm" "$BIN_DIR/helm"
    rm -rf "$HELM_TMP"
    _ok "helm 설치 완료: $(helm version --short)"
fi

# ── 5. Minikube 클러스터 시작 ────────────────────────────────────────────────
_info "Minikube 프로파일 확인: ${MINIKUBE_PROFILE}..."
if minikube status -p "${MINIKUBE_PROFILE}" 2>/dev/null | grep -q "Running"; then
    _ok "클러스터 이미 실행 중"
else
    _info "Minikube 클러스터 생성/시작 (driver=docker, k8s=${K8S_VERSION})..."
    minikube start \
        --profile "${MINIKUBE_PROFILE}" \
        --driver docker \
        --kubernetes-version "${K8S_VERSION}" \
        --cpus "${MINIKUBE_CPUS}" \
        --memory "${MINIKUBE_MEMORY}" \
        --embed-certs \
        --wait all
    _ok "클러스터 시작 완료"
fi

# kubectl context 전환
kubectl config use-context "${MINIKUBE_PROFILE}"
_ok "kubectl context: $(kubectl config current-context)"

# ── 6. 클러스터 기본 확인 ─────────────────────────────────────────────────────
_info "노드 상태 확인..."
kubectl wait --for=condition=Ready node --all --timeout=120s
kubectl get nodes -o wide

# ── 7. Helm repo 추가 ────────────────────────────────────────────────────────
_info "ingress-nginx Helm repo 추가..."
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx 2>/dev/null || true
helm repo update

# ── 8. 취약 ingress-nginx 설치 ───────────────────────────────────────────────
INGRESS_NS="ingress-nginx"
_info "ingress-nginx chart=${INGRESS_CHART_VERSION} (controller=${INGRESS_CONTROLLER_VERSION}) 설치..."

if helm status ingress-nginx -n "${INGRESS_NS}" 2>/dev/null | grep -q "deployed"; then
    _ok "ingress-nginx 이미 설치됨"
else
    kubectl create namespace "${INGRESS_NS}" --dry-run=client -o yaml | kubectl apply -f -

    helm install ingress-nginx ingress-nginx/ingress-nginx \
        --namespace "${INGRESS_NS}" \
        --version "${INGRESS_CHART_VERSION}" \
        --set controller.image.tag="${INGRESS_CONTROLLER_VERSION}" \
        --set controller.image.digest="${INGRESS_DIGEST}" \
        --set controller.admissionWebhooks.enabled=true \
        --set controller.admissionWebhooks.failurePolicy=Fail \
        --set controller.service.type=NodePort \
        --wait \
        --timeout 5m
    _ok "ingress-nginx 설치 완료"

    # PoC 재현을 위해 allow-snippet-annotations=true 설정
    # (v1.11.3 이미지에서 CVE-2025-1974 취약점 동작 조건)
    _info "ConfigMap 패치: allow-snippet-annotations=true..."
    kubectl patch configmap ingress-nginx-controller \
        -n "${INGRESS_NS}" \
        --type=merge \
        -p '{"data":{"allow-snippet-annotations":"true"}}'
    kubectl rollout restart deployment ingress-nginx-controller -n "${INGRESS_NS}"
    kubectl rollout status deployment ingress-nginx-controller -n "${INGRESS_NS}" --timeout=60s
    _ok "ConfigMap 패치 완료"
fi

# ── 9. 설치 확인 ──────────────────────────────────────────────────────────────
_info "ingress-nginx Pod 상태..."
kubectl get pods -n "${INGRESS_NS}" -o wide

_info "ValidatingWebhookConfiguration 확인..."
kubectl get validatingwebhookconfigurations | grep ingress || _warn "webhook 없음 — 재확인 필요"

_info "ingress-nginx 컨트롤러 버전 확인..."
kubectl get deploy ingress-nginx-controller -n "${INGRESS_NS}" \
    -o jsonpath='{.spec.template.spec.containers[0].image}' && echo ""

# ── 완료 ──────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Stage 2 완료!"
echo "  Minikube profile : ${MINIKUBE_PROFILE}"
echo "  Kubernetes        : ${K8S_VERSION}"
echo "  ingress-nginx     : chart ${INGRESS_CHART_VERSION} / controller ${INGRESS_CONTROLLER_VERSION}"
echo "  ※ controller ${INGRESS_CONTROLLER_VERSION} 은 CVE-2025-1974 취약 버전"
echo ""
echo "  다음 확인 명령:"
echo "    kubectl config current-context"
echo "    kubectl get pods -n ingress-nginx"
echo "    kubectl get validatingwebhookconfigurations"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
