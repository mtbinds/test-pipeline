#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

def collect_alerts(value):
    alerts = []

    if isinstance(value, dict):
        if isinstance(
            value.get("alerts"),
            list,
        ):
            alerts.extend(
                value["alerts"]
            )

        for child in value.values():
            alerts.extend(
                collect_alerts(child)
            )

    elif isinstance(value, list):
        for child in value:
            alerts.extend(
                collect_alerts(child)
            )

    return alerts

def main() -> None:
    report = Path(sys.argv[1])

    zap_exit = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].strip() else 0

    data = json.loads(
        report.read_text(
            encoding="utf-8"
        )
    )

    alerts = collect_alerts(
        data
    )

    print(
        f"ZAP alerts parsed: {len(alerts)}"
    )

    print(
        f"ZAP exit code: {zap_exit}"
    )

    if zap_exit == 1:
        print(
            "DAST policy: BLOCK"
        )

        raise SystemExit(30)

    if zap_exit == 2:
        print(
            "DAST policy: REVIEW"
        )

        return

    if zap_exit == 0:
        print(
            "DAST policy: PASS"
        )

        return

    print(
        "DAST tool execution error"
    )

    raise SystemExit(31)

if __name__ == "__main__":
    main()
