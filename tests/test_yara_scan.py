from pathlib import Path

import pytest

pytest.importorskip("yara")

from sentineltriage.yara_scan import scan_with_yara


def test_yara_detects_matching_sample(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("SentinelTriage YARA test marker", encoding="utf-8")

    rules = tmp_path / "test_rule.yar"
    rules.write_text(
        'rule SentinelTriage_Test {\n'
        '    strings:\n'
        '        $marker = "SentinelTriage YARA test marker" ascii\n'
        '    condition:\n'
        '        $marker\n'
        '}\n',
        encoding="utf-8",
    )

    result = scan_with_yara(str(sample), str(rules))

    assert "error" not in result
    assert result["scanned_files"] == 1
    assert any(
        match["rule"] == "SentinelTriage_Test"
        for match in result["matches"]
    )
    assert result["errors"] == []


def test_yara_reports_missing_target(tmp_path):
    rules = tmp_path / "test_rule.yar"
    rules.write_text(
        'rule TestRule { condition: true }',
        encoding="utf-8",
    )

    result = scan_with_yara(
        str(tmp_path / "missing.txt"),
        str(rules),
    )

    assert "error" in result
    assert result["matches"] == []


def test_yara_reports_missing_rules_file(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("test", encoding="utf-8")

    result = scan_with_yara(
        str(sample),
        str(tmp_path / "missing.yar"),
    )

    assert "error" in result
    assert result["matches"] == []


def test_yara_reports_invalid_rules(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("test", encoding="utf-8")

    rules = tmp_path / "invalid.yar"
    rules.write_text(
        "this is not a valid YARA rule",
        encoding="utf-8",
    )

    result = scan_with_yara(str(sample), str(rules))

    assert "error" in result
    assert result["matches"] == []
    assert "Could not compile YARA rules" in result["error"]
