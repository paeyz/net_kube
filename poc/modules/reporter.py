"""
결과 리포트 생성 모듈 — CVE-2025-1974

각 단계의 실행 결과를 JSON + Markdown으로 저장하고 터미널 요약을 출력한다.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class AttackReport:
    timestamp: str
    target: str
    enum_summary: dict | None
    token_info: dict | None
    lateral_results: list[dict] | None
    summary: dict = field(default_factory=dict)


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def build_report(
    target: str,
    enum_summary: dict | None = None,
    token_result=None,
    lateral_results=None,
) -> AttackReport:
    token_info = None
    if token_result and token_result.extract_success:
        token_info = {
            "method": token_result.method_used,
            "sa_name": token_result.sa_name,
            "namespace": token_result.namespace,
            "jwt_header": token_result.header,
            "token_preview": token_result.raw_token[:60] + "..." if token_result.raw_token else "",
        }

    lateral_dicts = []
    if lateral_results:
        for r in lateral_results:
            lateral_dicts.append({
                "level": r.level,
                "success": r.success,
                "details": r.details,
                "error": r.error,
            })

    # 요약
    summary = {
        "T1_file_enum": {
            "done": enum_summary is not None,
            "accessible_count": (enum_summary or {}).get("accessible_count", 0),
        },
        "T2_token_extract": {
            "done": token_result is not None,
            "success": bool(token_result and token_result.extract_success),
            "method": (token_result.method_used if token_result else ""),
        },
        "T3_lateral_move": {
            "done": bool(lateral_dicts),
            "levels_run": [r["level"] for r in lateral_dicts],
            "any_success": any(r["success"] for r in lateral_dicts),
        },
    }

    return AttackReport(
        timestamp=_ts(),
        target=target,
        enum_summary=enum_summary,
        token_info=token_info,
        lateral_results=lateral_dicts or None,
        summary=summary,
    )


def save_json(report: AttackReport, out_dir: str = "results") -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"attack_result_{report.timestamp}.json")
    data = {
        "timestamp": report.timestamp,
        "target": report.target,
        "summary": report.summary,
        "scenario_a_file_enum": report.enum_summary,
        "scenario_b_token": report.token_info,
        "scenario_c_lateral": report.lateral_results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


def save_markdown(report: AttackReport, out_dir: str = "results") -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"attack_result_{report.timestamp}.md")

    lines: list[str] = []
    lines.append("# CVE-2025-1974 공격 체인 실행 결과\n")
    lines.append(f"- **timestamp**: {report.timestamp}")
    lines.append(f"- **target**: {report.target}\n")

    lines.append("## T1 — 파일 열거 (시나리오 A)\n")
    if report.enum_summary:
        es = report.enum_summary
        lines.append(f"- 탐색 경로: {es.get('total_probed', 0)}개")
        lines.append(f"- 접근 가능: {es.get('accessible_count', 0)}개\n")
        lines.append("### 접근 가능 경로\n```")
        for p in es.get("accessible_files", []):
            lines.append(p)
        lines.append("```\n")
        lines.append("### 접근 불가 경로\n```")
        for p in es.get("inaccessible_files", []):
            lines.append(p)
        lines.append("```\n")
    else:
        lines.append("(실행 안 됨)\n")

    lines.append("## T2 — SA 토큰 추출 (시나리오 B)\n")
    if report.token_info:
        ti = report.token_info
        lines.append(f"- 추출 방법: `{ti['method']}`")
        lines.append(f"- ServiceAccount: `{ti['namespace']}/{ti['sa_name']}`")
        lines.append(f"- JWT 헤더: `{json.dumps(ti['jwt_header'])}`")
        lines.append(f"- 토큰 앞 60자: `{ti['token_preview']}`\n")
    else:
        lines.append("(추출 실패 또는 실행 안 됨)\n")

    lines.append("## T3 — Kubernetes API Lateral Movement (시나리오 C)\n")
    if report.lateral_results:
        for r in report.lateral_results:
            status = "성공" if r["success"] else "실패"
            lines.append(f"### Level {r['level']} — {status}\n")
            if r["error"]:
                lines.append(f"오류: {r['error']}\n")
            else:
                lines.append("```json")
                lines.append(json.dumps(r["details"], ensure_ascii=False, indent=2))
                lines.append("```\n")
    else:
        lines.append("(실행 안 됨 — T2 토큰 추출 실패)\n")

    lines.append("---\n")
    lines.append("## 요약\n")
    s = report.summary
    t1 = s.get("T1_file_enum", {})
    t2 = s.get("T2_token_extract", {})
    t3 = s.get("T3_lateral_move", {})
    lines.append(f"| 단계 | 결과 |")
    lines.append(f"|------|------|")
    lines.append(f"| T1 파일 열거 | 접근 가능 {t1.get('accessible_count', 0)}개 |")
    lines.append(f"| T2 토큰 추출 | {'성공 (' + t2.get('method','') + ')' if t2.get('success') else '실패'} |")
    lines.append(f"| T3 Lateral Move | {'성공' if t3.get('any_success') else '실패/미실행'} |")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def print_summary(report: AttackReport) -> None:
    width = 58
    print("\n" + "=" * width)
    print("  공격 체인 실행 결과 요약")
    print("=" * width)

    s = report.summary
    t1 = s.get("T1_file_enum", {})
    t2 = s.get("T2_token_extract", {})
    t3 = s.get("T3_lateral_move", {})

    def _mark(ok): return "[OK]  " if ok else "[FAIL]"

    print(f"  {_mark(t1.get('done'))} T1 파일 열거     — 접근가능 {t1.get('accessible_count', 0)}개 / {report.enum_summary.get('total_probed', 0) if report.enum_summary else 0}개")
    print(f"  {_mark(t2.get('success'))} T2 토큰 추출    — {'성공 (' + t2.get('method','') + ')' if t2.get('success') else '실패'}")
    print(f"  {_mark(t3.get('any_success'))} T3 Lateral Move — {'레벨 ' + str(t3.get('levels_run', [])) + ' 실행' if t3.get('done') else '스킵 (토큰 없음)'}")
    print("=" * width)
