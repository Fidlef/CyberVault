"""Local-only Flask interface for CyberVault."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

from flask import Flask, Request, render_template, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from crypto_core import VaultError, decrypt_bytes, encrypt_bytes

MAX_FILE_BYTES = 25 * 1024 * 1024


class InMemoryRequest(Request):
    """Keep multipart file parts in RAM instead of Werkzeug's spool file."""

    def _get_file_stream(
        self,
        total_content_length,
        content_type,
        filename=None,
        content_length=None,
    ):
        return BytesIO()


def create_app() -> Flask:
    app = Flask(__name__)
    app.request_class = InMemoryRequest
    app.config.update(
        MAX_CONTENT_LENGTH=MAX_FILE_BYTES + 1024 * 1024,
        TRUSTED_HOSTS=["127.0.0.1", "localhost"],
    )

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; base-uri 'none'"
        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/encrypt")
    def encrypt_route():
        upload = request.files.get("file")
        password = request.form.get("password", "")
        if not upload or not upload.filename:
            return render_template("index.html", error="Choose a file to encrypt."), 400
        if len(password) < 12:
            return render_template("index.html", error="Use a password with at least 12 characters."), 400
        data = upload.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            return render_template("index.html", error="The file is larger than the 25 MB local-demo limit."), 413
        result = encrypt_bytes(data, password)
        filename = (secure_filename(upload.filename) or "encrypted-file") + ".cvlt"
        return send_file(BytesIO(result), as_attachment=True, download_name=filename, mimetype="application/octet-stream")

    @app.post("/decrypt")
    def decrypt_route():
        upload = request.files.get("file")
        password = request.form.get("password", "")
        if not upload or not upload.filename or not password:
            return render_template("index.html", error="Choose a .cvlt file and enter its password."), 400
        data = upload.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            return render_template("index.html", error="The encrypted file is larger than the 25 MB local-demo limit."), 413
        try:
            result = decrypt_bytes(data, password)
        except VaultError as error:
            return render_template("index.html", error=str(error)), 400
        original = Path(secure_filename(upload.filename) or "decrypted-file").name
        filename = original[:-5] if original.lower().endswith(".cvlt") else f"decrypted-{original}"
        return send_file(BytesIO(result), as_attachment=True, download_name=filename or "decrypted-file", mimetype="application/octet-stream")

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error):
        return render_template("index.html", error="The request is larger than the 26 MB safety limit."), 413

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
