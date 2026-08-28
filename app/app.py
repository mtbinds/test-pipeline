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

    try:
        row = db().execute(
         "SELECT id, name FROM products WHERE id = ?",
         (product_id,),
        ).fetchone()
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
