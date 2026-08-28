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

    critical = []
    high = []

    for result in data.get("Results", []):
        for finding in (
            result.get(
                "Vulnerabilities",
                [],
            )
            or []
        ):
            severity = str(
                finding.get(
                    "Severity",
                    "",
                )
            ).upper()

            item = {
                "id": finding.get(
                    "VulnerabilityID",
                    "",
                ),
                "package": finding.get(
                    "PkgName",
                    "",
                ),
                "fixed": finding.get(
                    "FixedVersion",
                    "",
                ),
            }

            if severity == "CRITICAL":
                critical.append(item)

            elif severity == "HIGH":
                high.append(item)

    print(
        f"Trivy CRITICAL: {len(critical)}"
    )

    print(
        f"Trivy HIGH: {len(high)}"
    )

    if critical:
        print(
            "Container policy: BLOCK"
        )

        raise SystemExit(20)

    if high:
        print(
            "Container policy: REVIEW"
        )

    else:
        print(
            "Container policy: PASS"
        )

if __name__ == "__main__":
    main()
