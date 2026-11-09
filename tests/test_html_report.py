from html.parser import HTMLParser

from sentineltriage.html_report import write_html_report


class ReportParser(HTMLParser):
    def error(self, message):
        raise AssertionError(message)


def test_html_report_contains_case_and_file_hash(tmp_path):
    manifest = {
        "schema": "sentineltriage-evidence-v1",
        "case_id": "HTML-TEST-001",
        "operator": "Test Operator",
        "created_at_utc": "2026-10-22T00:00:00+00:00",
        "collection_mode": "read-only test",
        "findings": {
            "file_triage": {
                "files_inspected": 1,
                "files": [
                    {
                        "path": "sample.txt",
                        "size_bytes": 10,
                        "sha256": "a" * 64,
                        "indicators": [],
                    }
                ],
                "errors": [],
            },
            "yara": {
                "scanned_files": 1,
                "matches": [],
                "errors": [],
            },
        },
        "limitations": ["Test limitation"],
    }

    output = tmp_path / "report.html"
    write_html_report(manifest, str(output))
    content = output.read_text(encoding="utf-8")

    assert "HTML-TEST-001" in content
    assert "sample.txt" in content
    assert "a" * 64 in content
    assert "Test limitation" in content
    assert "Inventaris dan integritas file" in content


def test_html_report_escapes_untrusted_values(tmp_path):
    manifest = {
        "case_id": '<script>alert("x")</script>',
        "operator": "Test Operator",
        "findings": {
            "file_triage": {
                "files_inspected": 1,
                "files": [
                    {
                        "path": '<img src=x onerror="alert(1)">',
                        "size_bytes": 1,
                        "sha256": "b" * 64,
                        "indicators": [],
                    }
                ],
                "errors": [],
            }
        },
        "limitations": [],
    }

    output = tmp_path / "safe-report.html"
    write_html_report(manifest, str(output))
    content = output.read_text(encoding="utf-8")

    assert "<script>alert(" not in content
    assert '&lt;script&gt;' in content
    assert '&lt;img src=x' in content

    parser = ReportParser()
    parser.feed(content)
    parser.close()


def test_html_report_handles_empty_findings(tmp_path):
    manifest = {
        "case_id": "HTML-EMPTY-001",
        "operator": "Test Operator",
        "findings": {},
        "limitations": [],
    }

    output = tmp_path / "empty-report.html"
    write_html_report(manifest, str(output))
    content = output.read_text(encoding="utf-8")

    assert "HTML-EMPTY-001" in content
    assert "Tidak ada kecocokan YARA" in content
    assert output.exists()


def test_html_report_includes_network_assessment(tmp_path):
    manifest = {
        "case_id": "NETWORK-HTML-001",
        "operator": "Test Analyst",
        "findings": {
            "live_artifacts": {
                "network": {
                    "source": "lsof",
                    "collection_complete": False,
                    "items": [{
                        "process": "TestService",
                        "pid": 700,
                        "local_address": "*:7000",
                        "remote_address": None,
                        "status": "LISTEN",
                    }],
                    "errors": [],
                }
            }
        },
        "limitations": [],
    }

    output = tmp_path / "network-report.html"
    write_html_report(manifest, str(output))
    content = output.read_text(encoding="utf-8")

    assert "Penilaian awal koneksi jaringan" in content
    assert "Perlu ditinjau" in content
    assert "TestService" in content
    assert "semua interface" in content
    assert "bukan berarti koneksi berbahaya" in content


def test_html_report_includes_process_assessment(tmp_path):
    manifest = {
        "case_id": "PROCESS-HTML-001",
        "operator": "Test Analyst",
        "findings": {
            "live_artifacts": {
                "processes": {
                    "items": [{
                        "pid": 900,
                        "ppid": 1,
                        "name": "TestProcess",
                        "exe": "/private/tmp/test-process",
                        "username": "tester",
                        "status": "running",
                    }],
                    "errors": [],
                    "count": 1,
                    "collection_complete": True,
                }
            }
        },
        "limitations": [],
    }
    output = tmp_path / "process-report.html"
    write_html_report(manifest, str(output))
    content = output.read_text(encoding="utf-8")
    assert "Penilaian awal proses" in content
    assert "TestProcess" in content
    assert "Perlu ditinjau" in content
    assert "lokasi sementara" in content
    assert "bukan bukti malware" in content
