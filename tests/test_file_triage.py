import hashlib

from sentineltriage.file_triage import scan_directory


def test_sha256_matches_known_content(tmp_path):
    sample = tmp_path / "sample.txt"
    content = b"SentinelTriage integrity test"
    sample.write_bytes(content)

    result = scan_directory(str(sample))

    assert "error" not in result
    assert result["files_inspected"] == 1

    expected_hash = hashlib.sha256(content).hexdigest()
    file_result = result["files"][0]

    assert file_result["sha256"] == expected_hash


def test_missing_target_returns_error(tmp_path):
    missing = tmp_path / "does-not-exist.txt"

    result = scan_directory(str(missing))

    assert "error" in result
    assert result["files"] == []
    assert result["errors"] == []


def test_directory_scans_multiple_files(tmp_path):
    (tmp_path / "one.txt").write_text("first", encoding="utf-8")
    (tmp_path / "two.txt").write_text("second", encoding="utf-8")

    result = scan_directory(str(tmp_path))

    assert "error" not in result
    assert result["files_inspected"] == 2
    assert len(result["files"]) == 2
    assert result["errors"] == []


def test_jpeg_appended_data_indicator(tmp_path):
    sample = tmp_path / "test.jpg"

    # File uji minimal: JPEG signature, EOI marker, lalu data tambahan.
    sample.write_bytes(
        b"\xff\xd8"
        + b"\x00" * 32
        + b"\xff\xd9"
        + b"TEST-APPENDED-DATA"
    )

    result = scan_directory(str(sample))

    assert result["files_inspected"] == 1

    indicators = result["files"][0].get("indicators", [])
    indicator_types = [
        item.get("type") for item in indicators
    ]

    assert "possible_appended_data_after_jpeg_eoi" in indicator_types
