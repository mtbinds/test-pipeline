#!/usr/bin/env python3
"""
LAB22 IPSSI - Générateur du dépôt de laboratoire CI/CD sécurisé.

Le script crée :
- une application Flask synthétique ;
- des tests ;
- un Dockerfile ;
- des règles Semgrep ;
- une configuration Trivy ;
- une configuration ZAP Baseline ;
- une policy de quality gate ;
- un workflow GitHub Actions DevSecOps ;
- des scripts locaux de simulation/validation.

Aucun secret réel n'est créé.
Aucune cible externe n'est utilisée.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(".")
APP = ROOT / "app"
TESTS = ROOT / "tests"
WORKFLOWS = ROOT / ".github" / "workflows"
OUTPUTS = ROOT / "outputs"

APP_PY = r"""
from __future__ import annotations

import sqlite3
from flask import Flask, jsonify, request, make_response

app = Flask(__name__)

# Valeur purement synthétique pour le LAB.
TP22_DEMO_TOKEN = "TP22-SYNTHETIC-TOKEN-TRAINING-ONLY"

def db() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        "CREATE TABLE IF NOT EXISTS products "
        "(id INTEGER PRIMARY KEY, name TEXT)"
    )

    connection.execute(
        "INSERT OR IGNORE INTO products(id, name) "
        "VALUES (1, 'Keyboard')"
    )

    return connection

@app.after_request
def partial_security_headers(response):
    # L'un des headers est volontairement présent,
    # les autres restent absents pour ZAP Baseline.
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.get("/")
def index():
    response = make_response(
        "<html><head><title>TP22</title></head>"
        "<body><h1>Secure CI/CD Lab</h1></body></html>"
    )
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    return response

@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "lab": "tp22",
        }
    )

@app.get("/api/product")
def product():
    product_id = request.args.get("id", "1")

    # Construction volontairement imparfaite pour le SAST.
    query = (
        "SELECT id, name FROM products WHERE id = "
        + product_id
    )

    try:
        row = db().execute(query).fetchone()
    except Exception:
        return jsonify({"error": "invalid request"}), 400

    if row is None:
        return jsonify({"error": "not found"}), 404

    return jsonify(dict(row))

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8080,
        debug=False,
    )
"""

TEST_APP = r"""
from app.app import app

def test_health() -> None:
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"

def test_unknown_product() -> None:
    client = app.test_client()

    response = client.get("/api/product?id=999")

    assert response.status_code == 404

def test_content_type_options_header() -> None:
    client = app.test_client()

    response = client.get("/")

    assert response.headers[
        "X-Content-Type-Options"
    ] == "nosniff"
"""

REQUIREMENTS = """\
Flask==3.1.1
"""

REQUIREMENTS_DEV = """\
pytest==8.4.1
"""

DOCKERFILE = r"""
FROM python:3.12-slim-bookworm

RUN groupadd --gid 10001 app \
    && useradd \
       --uid 10001 \
       --gid 10001 \
       --no-create-home \
       --shell /usr/sbin/nologin \
       app

WORKDIR /app

COPY requirements.txt .

RUN python -m pip install \
    --no-cache-dir \
    -r requirements.txt

COPY --chown=10001:10001 app.py .

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

USER 10001:10001

CMD ["python", "app.py"]
"""

SEMGREP_RULES = r"""
rules:
  - id: tp22-sql-string-concatenation
    languages:
      - python
    severity: ERROR
    message: "Avoid constructing SQL through string concatenation."
    metadata:
      cwe:
        - "CWE-89"
      owasp:
        - "A03:2021 - Injection"
      category: security
    patterns:
      - pattern: |
          $QUERY = $A + $B

  - id: tp22-synthetic-token
    languages:
      - python
    severity: INFO
    message: "Synthetic training token detected."
    metadata:
      cwe:
        - "CWE-798"
      category: training
    pattern: TP22_DEMO_TOKEN = $VALUE
"""

TRIVY_CONFIG = r"""
format: json
exit-code: 0
ignore-unfixed: false

severity:
  - HIGH
  - CRITICAL

scan:
  scanners:
    - vuln
    - secret
"""

ZAP_CONFIG = r"""
# Rule ID   Action   Description
10020       FAIL     (X-Frame-Options Header Not Set)
10021       IGNORE   (X-Content-Type-Options Header Missing)
10038       WARN     (Content Security Policy Header Not Set)
"""

POLICY = r"""
policy:
  name: "TP22 Secure CI/CD Gate"

  tests:
    required: true
    failure: block

  sast:
    block_on:
      - ERROR

    review:
      - WARNING

    ignore:
      - INFO

  container:
    block_on:
      severities:
        - CRITICAL

    high_requires_review: true

  dast:
    zap_fail: block
    zap_warn: review

  workflow_security:
    minimum_permissions:
      contents: read

    forbidden_events:
      - pull_request_target

    require:
      - separate_security_jobs
      - artifact_retention
      - final_gate
      - no_plaintext_credentials

  decision:
    pass_values:
      - PASS

    review_values:
      - REVIEW

    block_values:
      - BLOCK
"""

WORKFLOW = r"""
name: TP22 DevSecOps Pipeline

on:
  pull_request:
  push:
    branches:
      - main
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: tp22-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

env:
  IMAGE_NAME: tp22-app
  IMAGE_TAG: ${{ github.sha }}

jobs:
  tests:
    name: Unit tests
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          python -m pip install \
            -r app/requirements.txt \
            -r requirements-dev.txt

      - name: Run tests
        run: |
          pytest -q \
            --junitxml=outputs/pytest.xml

      - name: Upload test evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: tp22-tests
          path: outputs/pytest.xml
          retention-days: 14

  sast:
    name: SAST - Semgrep CE
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run Semgrep JSON
        uses: docker://semgrep/semgrep:latest
        with:
          args: >
            semgrep scan
            --config semgrep-rules.yml
            --json
            --output outputs/semgrep.json
            app/

      - name: Run Semgrep SARIF
        uses: docker://semgrep/semgrep:latest
        with:
          args: >
            semgrep scan
            --config semgrep-rules.yml
            --sarif
            --output outputs/semgrep.sarif
            app/

      - name: Evaluate SAST policy
        run: |
          python scripts/evaluate_sast.py \
            outputs/semgrep.json

      - name: Upload SAST evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: tp22-sast
          path: |
            outputs/semgrep.json
            outputs/semgrep.sarif
          retention-days: 14

  build:
    name: Build container
    runs-on: ubuntu-latest
    needs:
      - tests
      - sast

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Build image
        run: |
          docker build \
            -t "${IMAGE_NAME}:${IMAGE_TAG}" \
            app/

      - name: Save image
        run: |
          docker save \
            "${IMAGE_NAME}:${IMAGE_TAG}" \
            -o outputs/tp22-image.tar

      - name: Upload image artifact
        uses: actions/upload-artifact@v4
        with:
          name: tp22-image
          path: outputs/tp22-image.tar
          retention-days: 1

  container_scan:
    name: Container scan - Trivy
    runs-on: ubuntu-latest
    needs:
      - build

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Download image
        uses: actions/download-artifact@v4
        with:
          name: tp22-image
          path: outputs/

      - name: Load image
        run: |
          docker load \
            -i outputs/tp22-image.tar

      - name: Run Trivy
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          image-ref: ${{ env.IMAGE_NAME }}:${{ env.IMAGE_TAG }}
          format: json
          output: outputs/trivy.json
          severity: HIGH,CRITICAL
          exit-code: "0"
          ignore-unfixed: false

      - name: Evaluate container policy
        run: |
          python scripts/evaluate_trivy.py \
            outputs/trivy.json

      - name: Upload Trivy evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: tp22-container-scan
          path: outputs/trivy.json
          retention-days: 14

  dast:
    name: DAST - ZAP Baseline
    runs-on: ubuntu-latest
    needs:
      - build

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Download image
        uses: actions/download-artifact@v4
        with:
          name: tp22-image
          path: outputs/

      - name: Load image
        run: |
          docker load \
            -i outputs/tp22-image.tar

      - name: Create network
        run: |
          docker network create tp22-ci

      - name: Start application
        run: |
          docker run \
            -d \
            --name tp22-ci-app \
            --network tp22-ci \
            "${IMAGE_NAME}:${IMAGE_TAG}"

      - name: Health check
        run: |
          for attempt in $(seq 1 30); do
            if docker run \
              --rm \
              --network tp22-ci \
              curlimages/curl:8.16.0 \
              -fsS \
              http://tp22-ci-app:8080/health
            then
              exit 0
            fi

            sleep 2
          done

          exit 1

      - name: ZAP Baseline
        id: zap
        continue-on-error: true
        run: |
          docker run \
            --rm \
            --network tp22-ci \
            -v "${PWD}/outputs:/zap/wrk:rw" \
            -v "${PWD}/zap-baseline.conf:/zap/wrk/zap-baseline.conf:ro" \
            ghcr.io/zaproxy/zaproxy:stable \
            zap-baseline.py \
            -t http://tp22-ci-app:8080 \
            -c /zap/wrk/zap-baseline.conf \
            -J zap.json \
            -r zap.html \
            -w zap.md \
            ; ZAP_EXIT=$?

          echo "exit_code=$ZAP_EXIT" \
            >> "$GITHUB_OUTPUT"

      - name: Evaluate ZAP policy
        run: |
          python scripts/evaluate_zap.py \
            outputs/zap.json \
            "${{ steps.zap.outputs.exit_code }}"

      - name: Upload DAST evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: tp22-dast
          path: |
            outputs/zap.json
            outputs/zap.html
            outputs/zap.md
          retention-days: 14

      - name: Teardown
        if: always()
        run: |
          docker rm \
            -f tp22-ci-app \
            || true

          docker network rm \
            tp22-ci \
            || true

  gate:
    name: Final security gate
    runs-on: ubuntu-latest
    if: always()
    needs:
      - tests
      - sast
      - build
      - container_scan
      - dast

    steps:
      - name: Decide
        env:
          TESTS_RESULT: ${{ needs.tests.result }}
          SAST_RESULT: ${{ needs.sast.result }}
          BUILD_RESULT: ${{ needs.build.result }}
          CONTAINER_RESULT: ${{ needs.container_scan.result }}
          DAST_RESULT: ${{ needs.dast.result }}
        run: |
          printf '%s\n' \
            "tests=$TESTS_RESULT" \
            "sast=$SAST_RESULT" \
            "build=$BUILD_RESULT" \
            "container=$CONTAINER_RESULT" \
            "dast=$DAST_RESULT"

          for value in \
            "$TESTS_RESULT" \
            "$SAST_RESULT" \
            "$BUILD_RESULT" \
            "$CONTAINER_RESULT" \
            "$DAST_RESULT"
          do
            if [ "$value" != "success" ]; then
              echo "BLOCK"
              exit 1
            fi
          done

          echo "PASS"
"""

EVALUATE_SAST = r"""
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
"""

EVALUATE_TRIVY = r"""
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
"""

EVALUATE_ZAP = r"""
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

    zap_exit = int(
        sys.argv[2]
    )

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
"""

VERIFY_WORKFLOW = r"""
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
"""

QUALITY = r"""
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
"""

def write(path: Path, content: str) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        content.strip() + "\n",
        encoding="utf-8",
    )

def main() -> None:
    APP.mkdir(
        parents=True,
        exist_ok=True,
    )

    TESTS.mkdir(
        parents=True,
        exist_ok=True,
    )

    WORKFLOWS.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUTS.mkdir(
        parents=True,
        exist_ok=True,
    )

    write(
        APP / "app.py",
        APP_PY,
    )

    write(
        APP / "requirements.txt",
        REQUIREMENTS,
    )

    write(
        APP / "Dockerfile",
        DOCKERFILE,
    )

    write(
        TESTS / "test_app.py",
        TEST_APP,
    )

    write(
        Path("requirements-dev.txt"),
        REQUIREMENTS_DEV,
    )

    write(
        Path("semgrep-rules.yml"),
        SEMGREP_RULES,
    )

    write(
        Path("trivy.yaml"),
        TRIVY_CONFIG,
    )

    write(
        Path("zap-baseline.conf"),
        ZAP_CONFIG,
    )

    write(
        Path("policy.yml"),
        POLICY,
    )

    write(
        WORKFLOWS / "devsecops.yml",
        WORKFLOW,
    )

    write(
        Path("scripts/evaluate_sast.py"),
        EVALUATE_SAST,
    )

    write(
        Path("scripts/evaluate_trivy.py"),
        EVALUATE_TRIVY,
    )

    write(
        Path("scripts/evaluate_zap.py"),
        EVALUATE_ZAP,
    )

    write(
        Path("scripts/verify_workflow.py"),
        VERIFY_WORKFLOW,
    )

    write(
        Path("scripts/quality_check_tp22.py"),
        QUALITY,
    )

    manifest = {
        "lab": "LAB22 Secure CI/CD Pipeline",
        "platform": "GitHub Actions",
        "controls": [
            "unit tests",
            "Semgrep SAST",
            "Docker build",
            "Trivy image scan",
            "ZAP Baseline DAST",
            "final policy gate",
        ],
        "security": [
            "least privilege GITHUB_TOKEN",
            "separated jobs",
            "artifact retention",
            "ephemeral runtime",
            "explicit final gate",
        ],
    }

    write(
        Path("lab-manifest.json"),
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False,
        ),
    )

    print("LAB22 generated.")
    print("Workflow: .github/workflows/devsecops.yml")
    print("Policy: policy.yml")
    print("Scripts: scripts/")

if __name__ == "__main__":
    main()