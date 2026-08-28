#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

def main() -> None:
    path = Path(sys.argv[1])

    data = json.loads(
        path.read_text(encoding="utf-8")
    )

    blocking = []

    for finding in data.get("results", []):
        severity = str(
            finding.get("extra", {}).get(
                "severity",
                "",
            )
        ).upper()

        if severity == "ERROR":
            blocking.append(
                finding.get("check_id", "")
            )

    print(
        f"SAST blocking findings: "
        f"{len(blocking)}"
    )

    for item in blocking:
        print(
            f"- {item}"
        )

    if blocking:
        raise SystemExit(10)

    print("SAST policy: PASS")

if __name__ == "__main__":
    main()
