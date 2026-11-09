
"""Evidence manifest and report writing helpers."""

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def build_manifest(case_id: str, operator: str, findings: dict) -> dict:
    """Build a timestamped evidence manifest."""
    return {
        "schema": "sentineltriage-evidence-v1",
        "case_id": case_id,
        "operator": operator,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "collection_mode": (
            "read-only triage; not a substitute for forensic imaging"
        ),
        "findings": findings,
        "limitations": [
            "Live collection may alter system state and can miss volatile evidence.",
            "SHA-256 supports integrity checking but does not by itself establish authenticity.",
            "YARA matches and file-structure anomalies require analyst validation.",
        ],
    }


def write_json(manifest: dict, output_path: str) -> None:
    """Write a readable JSON evidence manifest."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as stream:
        json.dump(
            manifest,
            stream,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        stream.write("\n")


def write_encrypted_json(
    manifest: dict,
    output_path: str,
    password: str,
) -> None:
    """Encrypt JSON using PBKDF2-HMAC-SHA256 and Fernet."""
    from cryptography.fernet import Fernet

    if not password or len(password) < 12:
        raise ValueError(
            "Use a password/passphrase of at least 12 characters."
        )

    # Generate a unique salt for this encrypted report.
    salt = os.urandom(16)

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000,
        dklen=32,
    )

    fernet_key = base64.urlsafe_b64encode(derived_key)

    plaintext = json.dumps(
        manifest,
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")

    encrypted_data = Fernet(fernet_key).encrypt(plaintext)

    # File format: magic header + salt + Fernet token.
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"STENC1" + salt + encrypted_data)


def write_pdf(
    manifest: dict,
    output_path: str,
    password: Optional[str] = None,
) -> None:
    """Create a PDF summary with optional password protection."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.pdfencrypt import StandardEncryption
    from reportlab.lib.utils import simpleSplit
    from reportlab.pdfgen import canvas

    if password is not None and not password:
        raise ValueError("PDF password cannot be empty.")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    encryption = None
    if password:
        encryption = StandardEncryption(
            password,
            ownerPassword=password + "-owner",
            canPrint=1,
            canModify=0,
            canCopy=0,
        )

    pdf = canvas.Canvas(
        str(path),
        pagesize=letter,
        encrypt=encryption,
    )

    width, height = letter
    y = height - 48

    def line(text: str, size: int = 9, bold: bool = False) -> None:
        nonlocal y

        font = "Helvetica-Bold" if bold else "Helvetica"
        wrapped_lines = simpleSplit(
            str(text),
            font,
            size,
            width - 90,
        )

        for part in wrapped_lines:
            if y < 54:
                pdf.showPage()
                y = height - 48

            pdf.setFont(font, size)
            pdf.drawString(45, y, part)
            y -= size + 5

    pdf.setTitle("SentinelTriage Evidence Report")
    pdf.setFillColor(colors.black)

    line("SentinelTriage - Digital Forensics Triage Report", 14, True)
    line("Case ID: {}".format(manifest.get("case_id")))
    line("Operator: {}".format(manifest.get("operator")))
    line("Created UTC: {}".format(manifest.get("created_at_utc")))
    line("Mode: {}".format(manifest.get("collection_mode")))

    line("", 8)
    line("Findings summary", 11, True)

    findings = manifest.get("findings", {})
    if isinstance(findings, dict):
        for section, value in findings.items():
            summary = json.dumps(
                value,
                ensure_ascii=False,
                default=str,
            )[:1200]
            line("[{}] {}".format(section, summary), 8)
    else:
        line(
            json.dumps(findings, ensure_ascii=False, default=str)[:1200],
            8,
        )

    line("", 8)
    line("Limitations", 11, True)

    for item in manifest.get("limitations", []):
        line("- {}".format(item), 8)

    pdf.save()
