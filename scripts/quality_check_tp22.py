#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

REQUIRED = [
    Path("app/app.py"),
    Path("app/Dockerfile"),
    Path("tests/test_app.py"),
    Path("requirements-dev.txt"),
    Path("semgrep-rules.yml"),
    Path("trivy.yaml"),
    Path("zap-baseline.conf"),
    Path("policy.yml"),
    Path(".github/workflows/devsecops.yml"),
    Path("scripts/evaluate_sast.py"),
    Path("scripts/evaluate_trivy.py"),
    Path("scripts/evaluate_zap.py"),
    Path("scripts/verify_workflow.py"),
]

def main() -> None:
    checks = [
        (
            f"file:{path}",
            (
                path.exists()
                and path.stat().st_size > 0
            ),
        )
        for path in REQUIRED
    ]

    passed = sum(
        ok
        for _name, ok in checks
    )

    print(
        f"Quality checks: "
        f"{passed}/{len(checks)}"
    )

    for name, ok in checks:
        print(
            f"[{'OK' if ok else 'FAIL'}] "
            f"{name}"
        )

    if passed != len(checks):
        raise SystemExit(
            "LAB22 quality gate incomplete."
        )

    print(
        "\nLAB22 repository structure is complete."
    )

if __name__ == "__main__":
    main()
