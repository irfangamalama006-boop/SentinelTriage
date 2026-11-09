
import json

from sentineltriage.reporting import (
    build_manifest,
    write_json,
    write_encrypted_json,
)


def test_build_manifest_contains_case_details():
    manifest = build_manifest(
        "TEST-AUTO-001",
        "Irfan Maulana",
        {"test": {"status": "ok"}},
    )

    assert manifest["case_id"] == "TEST-AUTO-001"
    assert manifest["operator"] == "Irfan Maulana"
    assert manifest["findings"]["test"]["status"] == "ok"
    assert manifest["schema"] == "sentineltriage-evidence-v1"


def test_write_json_creates_valid_report(tmp_path):
    manifest = build_manifest(
        "TEST-JSON-001",
        "Test Operator",
        {"test": {"status": "ok"}},
    )
    output = tmp_path / "report.json"

    write_json(manifest, str(output))

    assert output.exists()
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["case_id"] == "TEST-JSON-001"


def test_encrypted_report_can_be_decrypted(tmp_path):
    import base64
    import hashlib

    from cryptography.fernet import Fernet

    manifest = build_manifest(
        "TEST-ENC-001",
        "Test Operator",
        {"test": {"status": "ok"}},
    )
    output = tmp_path / "report.json.fernet"
    password = "TestPassphrase2026!"

    write_encrypted_json(manifest, str(output), password)

    data = output.read_bytes()
    assert data.startswith(b"STENC1")

    salt = data[6:22]
    token = data[22:]

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000,
        dklen=32,
    )
    fernet_key = base64.urlsafe_b64encode(key)

    decrypted = Fernet(fernet_key).decrypt(token)
    saved = json.loads(decrypted.decode("utf-8"))

    assert saved["case_id"] == "TEST-ENC-001"


def test_encrypted_report_rejects_wrong_password(tmp_path):
    import base64
    import hashlib

    import pytest
    from cryptography.fernet import Fernet, InvalidToken

    manifest = build_manifest(
        "TEST-ENC-002",
        "Test Operator",
        {"test": {"status": "ok"}},
    )
    output = tmp_path / "report.json.fernet"

    write_encrypted_json(
        manifest,
        str(output),
        "CorrectPassphrase2026!",
    )

    data = output.read_bytes()
    salt = data[6:22]
    token = data[22:]

    wrong_key = hashlib.pbkdf2_hmac(
        "sha256",
        b"WrongPassphrase2026!",
        salt,
        600_000,
        dklen=32,
    )
    fernet_key = base64.urlsafe_b64encode(wrong_key)

    with pytest.raises(InvalidToken):
        Fernet(fernet_key).decrypt(token)
