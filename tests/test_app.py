from io import BytesIO

from app import create_app


def test_index_has_no_store_security_headers():
    response = create_app().test_client().get("/")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_encrypt_route_requires_long_password():
    response = create_app().test_client().post("/encrypt", data={"password":"short", "file":(BytesIO(b"data"), "demo.txt")})
    assert response.status_code == 400
    assert b"at least 12 characters" in response.data


def test_route_round_trip():
    client = create_app().test_client()
    encrypted = client.post("/encrypt", data={"password":"correct horse battery", "file":(BytesIO(b"synthetic document"), "demo.txt")})
    assert encrypted.status_code == 200
    decrypted = client.post("/decrypt", data={"password":"correct horse battery", "file":(BytesIO(encrypted.data), "demo.txt.cvlt")})
    assert decrypted.status_code == 200
    assert decrypted.data == b"synthetic document"
