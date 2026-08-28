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
