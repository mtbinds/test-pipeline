#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(
    ".github/workflows/devsecops.yml"
)

def main() -> None:
    data = yaml.safe_load(
        WORKFLOW.read_text(
            encoding="utf-8"
        )
    )

    checks = []

    permissions = data.get(
        "permissions",
        {},
    )

    checks.append(
        (
            "contents-read",
            permissions.get(
                "contents"
            )
            == "read",
        )
    )

    trigger = data.get(
        True,
        data.get(
            "on",
            {},
        ),
    )

    trigger_text = str(
        trigger
    )

    checks.append(
        (
            "no-pull-request-target",
            "pull_request_target"
            not in trigger_text,
        )
    )

    jobs = data.get(
        "jobs",
        {},
    )

    for required in [
        "tests",
        "sast",
        "build",
        "container_scan",
        "dast",
        "gate",
    ]:
        checks.append(
            (
                f"job:{required}",
                required in jobs,
            )
        )

    checks.append(
        (
            "final-gate-needs-security-jobs",
            set(
                jobs.get(
                    "gate",
                    {},
                ).get(
                    "needs",
                    [],
                )
            )
            >= {
                "tests",
                "sast",
                "build",
                "container_scan",
                "dast",
            },
        )
    )

    text = WORKFLOW.read_text(
        encoding="utf-8"
    )

    checks.append(
        (
            "artifact-retention",
            "retention-days:"
            in text,
        )
    )

    checks.append(
        (
            "no-plaintext-password-pattern",
            "password="
            not in text.lower(),
        )
    )

    passed = sum(
        ok
        for _name, ok in checks
    )

    print(
        f"Workflow checks: "
        f"{passed}/{len(checks)}"
    )

    for name, ok in checks:
        print(
            f"[{'OK' if ok else 'FAIL'}] "
            f"{name}"
        )

    if passed != len(checks):
        raise SystemExit(
            "Workflow security validation failed."
        )

if __name__ == "__main__":
    main()
