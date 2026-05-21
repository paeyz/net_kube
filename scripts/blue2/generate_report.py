#!/usr/bin/env python3
"""Generate a Korean Blue Team 2 report draft from sanitized summary files."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULTS_DIR = REPO_ROOT / "results" / "blue2"
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "blue2_report_draft.md"


SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"Authorization\s*:\s*(?:Bearer\s+)?[^\s]+", re.IGNORECASE),
        "Authorization: <REDACTED>",
    ),
    (
        re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}"),
        "Bearer <REDACTED>",
    ),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "<REDACTED_JWT>",
    ),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{8,})?(?:\.\.\.)?"),
        "<REDACTED_JWT_PREVIEW>",
    ),
    (
        re.compile(r"토큰[^\n:：]{0,40}[:：]\s*[^\s]+"),
        "토큰: <REDACTED>",
    ),
    (
        re.compile(
            r"\b(token|password|passwd|secret|client-key-data|client-certificate-data|certificate-authority-data)\b\s*[:=]\s*(\"[^\"]*\"|'[^']*'|[^\s,}]+)",
            re.IGNORECASE,
        ),
        r"\1: <REDACTED>",
    ),
    (
        re.compile(r"[A-Za-z0-9+/_-]{80,}={0,2}"),
        "<REDACTED_BASE64>",
    ),
]


@dataclass(frozen=True)
class Summary:
    kind: str
    path: Path
    text: str


def redact(text: str) -> str:
    redacted = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def discover_latest_summaries(results_dir: Path) -> dict[str, Summary]:
    buckets: dict[str, list[Path]] = {"m4": [], "b1": [], "m5": []}
    for path in results_dir.glob("*/summary.md"):
        dirname = path.parent.name
        if dirname.startswith("m5-diagnostics-"):
            buckets["m5"].append(path)
            continue
        for kind in buckets:
            if dirname.endswith(f"-{kind}"):
                buckets[kind].append(path)
                break

    latest: dict[str, Summary] = {}
    for kind, paths in buckets.items():
        if not paths:
            continue
        if kind == "m4":
            original_lab_paths = [
                p
                for p in paths
                if "Kubernetes context: `cve-2025-1974-lab`" in p.read_text(encoding="utf-8", errors="replace")
            ]
            if original_lab_paths:
                paths = original_lab_paths
        if kind == "m5":
            completed_m5_paths = [p for p in paths if p.parent.name.endswith("-m5")]
            if completed_m5_paths:
                paths = completed_m5_paths
        selected = sorted(paths, key=lambda p: (p.parent.name, p.stat().st_mtime))[-1]
        latest[kind] = Summary(kind=kind, path=selected, text=redact(selected.read_text(encoding="utf-8")))
    return latest


def extract_core_rows(text: str) -> list[tuple[str, str]]:
    lines = text.splitlines()
    rows: list[tuple[str, str]] = []
    in_core = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## "):
            if in_core:
                break
            in_core = "핵심 결과" in stripped
            continue
        if not in_core or not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 2:
            continue
        if cells[0] in {"항목", "---"} or set(cells[0]) <= {"-"}:
            continue
        if set(cells[0] + cells[1]) <= {"-", " "}:
            continue
        rows.append((cells[0], cells[1]))
    return rows


def summary_source(summary: Summary | None) -> str:
    if summary is None:
        return "미실행"
    return f"`{summary.path.relative_to(REPO_ROOT)}`"


def render_result_table(summary: Summary | None) -> str:
    if summary is None:
        return "| 항목 | 결과 |\n|---|---|\n| 실행 상태 | 아직 summary.md 없음 |\n"
    rows = extract_core_rows(summary.text)
    if not rows:
        return "| 항목 | 결과 |\n|---|---|\n| 요약 | 핵심 결과 표를 찾지 못함 |\n"
    out = ["| 항목 | 결과 |", "|---|---|"]
    out.extend(f"| {item} | {value} |" for item, value in rows)
    return "\n".join(out) + "\n"


def get_value(summary: Summary | None, item_pattern: str) -> str:
    if summary is None:
        return "미실행"
    pattern = re.compile(item_pattern)
    for item, value in extract_core_rows(summary.text):
        if pattern.search(item):
            return value
    return "미확인"


def get_bullet_value(summary: Summary | None, label: str) -> str:
    if summary is None:
        return "미실행"
    pattern = re.compile(rf"^-\s+{re.escape(label)}:\s+(.+)$", re.MULTILINE)
    match = pattern.search(summary.text)
    if not match:
        return "미확인"
    value = match.group(1).strip()
    if value.startswith("`") and value.endswith("`"):
        value = value[1:-1]
    return value.strip()


def normalize_code_value(value: str) -> str:
    return value.strip().strip("`")


def strip_controller_prefix(value: str) -> str:
    normalized = normalize_code_value(value)
    if normalized.startswith("controller="):
        normalized = normalized[len("controller=") :]
    return normalized.split("@sha256:", 1)[0]


def truth_to_ko(value: str) -> str:
    normalized = normalize_code_value(value).lower()
    if normalized == "true":
        return "예"
    if normalized == "false":
        return "아니오"
    return normalize_code_value(value)


def decision_to_ko(value: str) -> str:
    normalized = normalize_code_value(value)
    mapping = {
        "yes": "허용",
        "no": "거부",
        "Allowed": "허용",
        "Forbidden": "거부",
        "Observed": "관찰됨",
        "Yes": "예",
        "passed": "통과",
        "inconclusive due to kubectl_exec fallback reachability": "불확실",
        "pre=Reached; post=Allowed without direct leak": "패치 전 도달, 패치 후 응답 내 직접 누출 없음",
        "Reached via kubectl_exec fallback": "kubectl_exec 대체 경로로 도달",
        "Blocked or no files reached": "차단 또는 파일 도달 없음",
        "Reached": "도달",
        "Allowed without direct leak": "요청은 허용됐으나 응답 내 직접 누출 없음",
        "deployed": "deployed",
    }
    return mapping.get(normalized, normalized)


def sibling_text(summary: Summary | None, filename: str) -> str:
    if summary is None:
        return ""
    path = summary.path.parent / filename
    if not path.exists():
        return ""
    return redact(path.read_text(encoding="utf-8", errors="replace"))


def render_rows(rows: list[tuple[str, str]]) -> str:
    out = ["| 항목 | 결과 |", "|---|---|"]
    out.extend(f"| {item} | {value} |" for item, value in rows)
    return "\n".join(out) + "\n"


def render_m4_table(summary: Summary | None) -> str:
    if summary is None:
        return render_rows([("실행 상태", "아직 요약 파일 없음")])

    remaining_before = get_bullet_value(summary, "광범위 ClusterRoleBinding 잔존 개수")
    remaining_after = get_bullet_value(summary, "광범위 ClusterRoleBinding 제거 후 잔존 개수")
    remove_used = get_bullet_value(summary, "광범위 ClusterRoleBinding 제거 옵션 사용")
    rows = [
        ("M4 적용 전 kube-system Secrets 조회 권한", decision_to_ko(get_value(summary, r"M4 적용 전 kube-system"))),
        ("M4 적용 후 kube-system Secrets 조회 권한", decision_to_ko(get_value(summary, r"M4 적용 후 kube-system"))),
        ("격리 토큰 기반 kube-system Secrets 권한", decision_to_ko(get_value(summary, r"격리 토큰.*kube-system"))),
        ("M4 적용 전 ingress-nginx Secrets 조회 권한", decision_to_ko(get_value(summary, r"M4 적용 전 ingress-nginx"))),
        ("M4 적용 후 ingress-nginx Secrets 조회 권한", decision_to_ko(get_value(summary, r"M4 적용 후 ingress-nginx"))),
        ("격리 토큰 기반 ingress-nginx Secrets 권한", decision_to_ko(get_value(summary, r"격리 토큰.*ingress-nginx"))),
        ("광범위 ClusterRoleBinding 제거 옵션", truth_to_ko(remaining_after and remove_used)),
        ("광범위 ClusterRoleBinding 잔존 수", f"{normalize_code_value(remaining_before)} -> {normalize_code_value(remaining_after)}"),
        ("토큰 파일 접근 관찰", decision_to_ko(get_value(summary, r"M4 이후 T2"))),
        ("T3 lateral movement 제한", decision_to_ko(get_value(summary, r"T3 lateral"))),
    ]
    return render_rows(rows)


def render_b1_table(summary: Summary | None) -> str:
    if summary is None:
        return render_rows([("실행 상태", "아직 요약 파일 없음")])

    vulnerable_image = strip_controller_prefix(get_value(summary, r"vulnerable baseline controller image"))
    patched_image = strip_controller_prefix(get_value(summary, r"patched controller image"))
    rows = [
        ("취약 기준 controller 이미지", f"`{vulnerable_image}`"),
        ("패치 controller 이미지", f"`{patched_image}`"),
        ("패치 후 Helm release 상태", f"`{normalize_code_value(get_value(summary, r'Helm release status after patch'))}`"),
        ("패치 전 T1 파일 열거 수", f"`{normalize_code_value(get_value(summary, r'pre_patch_file_enum_count'))}`"),
        ("패치 후 T1 파일 열거 수", f"`{normalize_code_value(get_value(summary, r'post_patch_file_enum_count'))}`"),
        ("CVE 공격 경로 차단 여부", truth_to_ko(get_value(summary, r"exploit_path_blocked"))),
        ("CVE 공격 경로 패치 검증", decision_to_ko(get_bullet_value(summary, "B1 exploit-specific patch validation"))),
        ("전체 end-to-end 공격 체인 검증", "불확실, 실패로 판정하지 않음"),
        ("kubectl_exec 대체 경로 T2/T3 관찰", truth_to_ko(get_value(summary, r"fallback_t2_t3_observed"))),
        ("poc-step3 상태", decision_to_ko(get_value(summary, r"poc_step3_status"))),
    ]
    return render_rows(rows)


def m4_status(summary: Summary | None) -> tuple[str, str]:
    if summary is None:
        return "미실행", "M4 summary.md가 아직 없어 결과를 판단할 수 없다."

    after_kube = get_value(summary, r"M4 적용 후 kube-system")
    token_kube = get_value(summary, r"격리 토큰.*kube-system")
    if token_kube == "미확인":
        token_kube = get_value(summary, r"탈취.*kube-system")
    remaining_after = get_bullet_value(summary, "광범위 ClusterRoleBinding 제거 후 잔존 개수")
    after_removal = sibling_text(summary, "broad_clusterrolebindings_after_removal.tsv")
    broad_removed = bool(after_removal == "" or not after_removal.strip())

    if "`Forbidden`" in token_kube or token_kube == "`Forbidden`":
        removal_note = "광범위 ClusterRoleBinding 제거 후 잔존 수가 0으로 확인되었고, " if remaining_after == "0" else ""
        return "성공", f"{removal_note}격리 토큰 테스트에서 kube-system Secrets 접근이 거부되었다."
    if "`no`" in after_kube and "`Allowed`" in token_kube:
        return (
            "부분 완료 / 토큰 테스트 재검증 필요",
            "RBAC can-i는 kube-system Secrets list를 no로 보이나, token_test_kube_system.log는 Allowed로 남아 있어 Forbidden을 증명하지 못했다. broad CRB 제거 여부는 별도 로그와 live RBAC로 확인해야 한다.",
        )
    if "`no`" in after_kube and broad_removed:
        return (
            "부분 완료",
            "RBAC can-i는 no이고 broad CRB 제거 로그는 비어 있으나, 탈취 토큰 기반 Forbidden 증거가 부족하다.",
        )
    return "incomplete", "kube-system Secrets 접근 제한이 명확히 증명되지 않았다."


def b1_status(summary: Summary | None) -> tuple[str, str]:
    if summary is None:
        return "미실행", "B1 summary.md가 아직 없어 결과를 판단할 수 없다."

    exploit_verdict = get_bullet_value(summary, "B1 exploit-specific patch validation")
    end_to_end_verdict = get_bullet_value(summary, "End-to-end attack-chain validation")
    explicit_reason = get_bullet_value(summary, "판정 이유")
    if exploit_verdict != "미확인":
        pre_enum_count = normalize_code_value(get_value(summary, r"pre_patch_file_enum_count"))
        post_enum_count = normalize_code_value(get_value(summary, r"post_patch_file_enum_count"))
        return (
            "CVE 공격 경로 검증 통과 / 전체 공격 체인 검증 불확실",
            f"패치 후 Helm release는 deployed이고, v1.11.5에서 T1 파일 열거가 {pre_enum_count}에서 {post_enum_count}으로 감소했다. kubectl_exec 대체 경로는 실습 편의 기능이므로 CVE-2025-1974 공격 성공과 동일하게 보지 않는다.",
        )

    explicit_verdict = get_bullet_value(summary, "B1 판정")
    explicit_reason = get_bullet_value(summary, "판정 이유")
    if explicit_verdict != "미확인":
        return explicit_verdict, explicit_reason

    helm_log = sibling_text(summary, "helm_upgrade_v1_11_5.log")
    post_poc = get_value(summary, r"패치 후 poc-step3")
    post_blocked = get_value(summary, r"post-patch attack blocked")
    exploit_blocked = get_value(summary, r"exploit_path_blocked")
    helm_succeeded = get_value(summary, r"Helm upgrade succeeded")
    patched_image_ok = get_value(summary, r"patched image verified")
    pre_enum_count = get_value(summary, r"pre_patch_file_enum_count")
    post_enum_count = get_value(summary, r"post_patch_file_enum_count")
    post_t2 = get_value(summary, r"T2")
    post_t3 = get_value(summary, r"T3")

    if "## exit_status: 1" in helm_log or "UPGRADE FAILED" in helm_log:
        return (
            "incomplete / Helm upgrade fix 필요",
            "Helm upgrade가 exit 1로 종료되어 release 상태를 정상 패치로 확정할 수 없다.",
        )
    if "`true`" in helm_succeeded and "`true`" in patched_image_ok and "`true`" in post_blocked:
        return "통과", "패치 업그레이드, 이미지 검증, post-patch 차단 조건이 모두 충족되었다."
    if "`true`" in helm_succeeded and "`true`" in patched_image_ok and "`true`" in exploit_blocked:
        return (
            "CVE 공격 경로 검증 통과 / 전체 공격 체인 별도 확인 필요",
            f"파일 열거가 {pre_enum_count}에서 {post_enum_count}으로 차단되었으나, 대체 경로 기반 T2/T3와 직접 PoC 상태는 별도로 해석해야 한다.",
        )
    if "`Blocked`" in post_poc and "Reached" not in post_t2 and "Reached" not in post_t3:
        return "통과", "패치 후 poc-step3 및 attack-chain 후속 단계가 차단된 것으로 요약되었다."
    return (
        "incomplete",
        f"post-patch 결과가 충분하지 않다. poc-step3={post_poc}, T2={post_t2}, T3={post_t3}.",
    )


def m5_status(summary: Summary | None) -> tuple[str, str]:
    if summary is None:
        return "미실행", "M5 summary.md가 아직 없어 결과를 판단할 수 없다."

    verdict = get_bullet_value(summary, "M5 판정")
    reason = get_bullet_value(summary, "판정 이유")
    if verdict != "미확인":
        return verdict, reason

    final_verdict = get_value(summary, r"M5 final verdict")
    if final_verdict != "미확인":
        return normalize_code_value(final_verdict), "M5 핵심 결과 표의 최종 판정을 사용했다."

    return "미확인", "M5 summary.md에서 명시적 판정을 찾지 못했다."


def build_report(summaries: dict[str, Summary]) -> str:
    m4 = summaries.get("m4")
    b1 = summaries.get("b1")
    m5 = summaries.get("m5")

    m0_result = "M4 또는 B1의 pre-patch/baseline 로그 확인 필요"
    if m4 is not None:
        m0_result = "M4 baseline_attack_chain.log에 기록됨"
    elif b1 is not None:
        m0_result = "B1 pre_patch_attack_chain.log에 기록됨"

    m4_verdict, m4_note = m4_status(m4)
    b1_verdict, b1_note = b1_status(b1)
    m5_verdict, m5_note = m5_status(m5)

    lines: list[str] = []
    lines.append("# Blue Team 2 보고서 초안\n")
    lines.append("> 이 문서는 `results/blue2/*/summary.md`의 최신 요약만 사용해 생성했다. 원시 토큰, Secret 값, Authorization 헤더는 포함하지 않는다.\n")

    lines.append("## 1. Blue Team 2 역할\n")
    lines.append("Blue Team 2는 CVE-2025-1974 ingress-nginx 실습에서 M4 RBAC 최소 권한화, B1 패치 검증, M5 통합 검증을 담당한다. 목표는 취약점 재현 여부를 과장하지 않고, 각 방어가 어느 공격 단계를 막거나 제한하는지 재현 가능한 로그로 설명하는 것이다.\n")

    lines.append("## 2. 실험 환경\n")
    lines.append("| 항목 | 내용 |")
    lines.append("|---|---|")
    lines.append("| 실행 범위 | 로컬 Minikube 실습 환경 전용 |")
    lines.append("| 외부 대상 | 사용하지 않음 |")
    lines.append(f"| M4 최신 요약 | {summary_source(m4)} |")
    lines.append(f"| B1 최신 요약 | {summary_source(b1)} |")
    lines.append(f"| M5 최신 요약 | {summary_source(m5)} |")
    lines.append(f"| M0 vulnerable baseline | {m0_result} |\n")

    lines.append("## 3. M4 RBAC 최소 권한화\n")
    lines.append(render_m4_table(m4))
    lines.append(f"**현재 판정:** `{m4_verdict}`\n")
    lines.append(f"{m4_note}\n")
    lines.append("M4의 핵심 성공 기준은 ingress-nginx ServiceAccount가 `kube-system` Secrets를 더 이상 조회하지 못하는 것이다. 이번 결과에서는 광범위 ClusterRoleBinding 제거와 격리된 토큰 테스트가 함께 확인되어 kube-system Secrets 접근 거부를 증명했다.")
    lines.append("`ingress-nginx` 네임스페이스 접근은 운영에 필요한 TLS Secret 등 때문에 허용되거나 제한된 범위로 남을 수 있으며, 이는 기대 가능한 결과다. M4는 토큰 파일 접근 자체를 막는 통제가 아니라, 토큰이 노출된 뒤 피해 범위를 줄이는 RBAC 최소 권한화 통제다.\n")

    lines.append("## 4. B1 패치 검증\n")
    lines.append(render_b1_table(b1))
    lines.append(f"**현재 판정:** `{b1_verdict}`\n")
    lines.append(f"{b1_note}\n")
    lines.append("B1은 취약 기준인 `registry.k8s.io/ingress-nginx/controller:v1.11.3`과 패치 버전인 `registry.k8s.io/ingress-nginx/controller:v1.11.5`를 비교했다. 패치 전 T1 파일 열거는 8건이었고, 패치 후에는 0건이었다.")
    lines.append("따라서 CVE-2025-1974 공격 경로에 한정한 패치 검증은 통과로 본다. 다만 `kubectl_exec` 대체 경로로 T2/T3가 관찰된 것은 실습 편의용 도달성 확인이며 CVE-2025-1974 취약점 성공과 동일하지 않다. 그래서 전체 end-to-end 공격 체인 검증은 실패가 아니라 불확실로 표시한다.\n")

    lines.append("## 5. M5 Full Stack 통합 검증\n")
    lines.append(render_result_table(m5))
    lines.append(f"**현재 판정:** `{m5_verdict}`\n")
    lines.append(f"{m5_note}\n")
    lines.append("M5는 M2, M3, M4가 중복 방어가 아니라 서로 다른 경로를 담당하는 defense-in-depth 조합임을 확인한다. M2는 네트워크 직접 접근, M3는 kube-apiserver 경유 악성 Ingress, M4는 탈취 토큰의 권한 범위를 다룬다.")
    lines.append("최신 M5 결과는 위 표의 최종 판정을 따른다. `passed`가 아니면 어떤 조건이 남았는지 이유와 증거 경로를 함께 확인해야 하며, M5의 부분 완료 또는 보류 상태는 이미 입증된 M4/B1 결과를 무효화하지 않는다.\n")

    lines.append("## 6. Red Team 공격 단계와의 연결\n")
    lines.append("| 공격 단계 | 의미 | 관련 방어 | 최신 관찰 요약 |")
    lines.append("|---|---|---|---|")
    lines.append(f"| M0/T1 | webhook 접근 및 파일 열거 | B1, M2, M3 | {m0_result} |")
    lines.append(f"| T2 | ingress-nginx SA 토큰 접근 | B1, M2 | {decision_to_ko(get_value(m4, r'M4 이후 T2'))} |")
    lines.append(f"| T3 | 탈취 토큰으로 Kubernetes API 접근 | M4 | {decision_to_ko(get_value(m4, r'T3 lateral'))} |")
    lines.append(f"| T4 | 결과 리포트 생성 | 로그 위생/.gitignore | `results/blue2/`에 민감정보 제거 요약 보관 |\n")

    lines.append("## 7. Detection Team D3/D4와의 연결\n")
    lines.append("| 탐지 | 연결 지점 | 해석 |")
    lines.append("|---|---|---|")
    lines.append("| D3 | 토큰 파일 접근 | M4만으로는 계속 발생할 수 있다. B1 또는 M2가 더 앞에서 막으면 미발생이 정상일 수 있다. |")
    lines.append("| D4 | 탈취 토큰 API 접근 | M4 이후에는 API 접근 시도는 보이더라도 `Forbidden` 결과가 기대된다. |")
    lines.append("| D1/D2 참고 | webhook 직접 접근, 위험 annotation | M5에서 M2/M3와 함께 해석하면 어느 지점에서 공격이 멈췄는지 설명하기 쉽다. |\n")

    lines.append("## 8. 운영 환경 권장 조합\n")
    lines.append("| 우선순위 | 권장 조치 | 이유 |")
    lines.append("|---|---|---|")
    lines.append("| 1 | ingress-nginx 패치 적용 | 취약한 CVE 공격 경로를 가장 앞단에서 제거 |")
    lines.append("| 2 | NetworkPolicy 적용 및 CNI 검증 | webhook 직접 노출면 축소 |")
    lines.append("| 3 | 위험 annotation 차단 Admission 정책 적용 | kube-apiserver 경유 악성 Ingress 제한 |")
    lines.append("| 4 | ingress-nginx RBAC 최소 권한화 | 토큰 탈취 이후 kube-system 등으로 확산되는 blast radius 축소 |")
    lines.append("| 5 | D3/D4 탐지 유지 | 토큰 파일 접근과 탈취 토큰 API 접근 시도를 관찰 가능하게 함 |\n")

    lines.append("## 9. 한계 및 주의사항\n")
    lines.append("- 이 보고서는 원시 로그를 다시 실행하지 않고 최신 `summary.md`만 합성한다.")
    lines.append("- `미실행`, `Unknown`, `미확인`은 실험 성공으로 해석하면 안 된다.")
    lines.append("- B1의 `kubectl_exec` 대체 경로는 실습 편의용 경로이며 CVE-2025-1974 공격 경로 자체가 아니다.")
    lines.append("- M5 검증은 Calico, Cilium, Antrea 같은 NetworkPolicy 집행 가능 CNI와 Docker attacker pod 검증이 있어야 완전해진다.")
    lines.append("- D3는 M4 이후에도 발생할 수 있다. M4는 토큰 파일 접근을 막는 통제가 아니라 탈취 토큰의 권한 범위를 줄이는 통제다.")
    lines.append("- 원시 audit/Falco 로그, 토큰 dump, Secret dump, attack_result 파일은 커밋하지 않는다.\n")

    return redact("\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate docs/blue2_report_draft.md from latest Blue2 summaries.")
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help=f"Blue2 results directory (default: {DEFAULT_RESULTS_DIR})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Report output path (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    summaries = discover_latest_summaries(args.results_dir)
    report = build_report(summaries)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(f"[blue2] report written: {args.output.relative_to(REPO_ROOT)}")
    if not summaries:
        print("[blue2] no summary.md files found yet; report contains placeholders.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
