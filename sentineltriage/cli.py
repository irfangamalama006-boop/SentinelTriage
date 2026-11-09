import argparse
import getpass
import json
from datetime import datetime, timezone
from pathlib import Path

from .collector import (
    collect_host_info,
    collect_processes,
    collect_network,
    collect_windows_registry,
    collect_event_log_metadata,
)
from .file_triage import scan_directory
from .yara_scan import scan_with_yara
from .reporting import (
    build_manifest,
    write_json,
    write_pdf,
    write_encrypted_json,
)
from .html_report import write_html_report
from .timeline import build_timeline, write_timeline_json


def utc_now():
    """Return the current time as timezone-aware UTC ISO-8601."""
    return datetime.now(timezone.utc).isoformat()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Read-only defensive digital forensics triage"
    )
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--output", default="sentineltriage-output")
    parser.add_argument("--collect-live", action="store_true")
    parser.add_argument("--scan", help="File or directory to inspect and hash")
    parser.add_argument(
        "--yara-rules",
        help="Path to a YARA rules file; used with --scan",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt JSON and password-protect PDF",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    findings = {}
    events = []

    if args.collect_live:
        collectors = [
            ("host", "Informasi perangkat dikumpulkan", collect_host_info),
            ("processes", "Daftar proses dikumpulkan", collect_processes),
            ("network", "Koneksi jaringan dikumpulkan", collect_network),
            ("registry_run_keys", "Windows Registry diperiksa", collect_windows_registry),
            ("event_logs", "Metadata Event Logs diperiksa", collect_event_log_metadata),
        ]

        live_artifacts = {}

        for key, label, collector in collectors:
            result = collector()
            live_artifacts[key] = result

            if key == "host":
                count = 1
                status = "complete"
            else:
                count = result.get("count", 0) if isinstance(result, dict) else 0
                errors = result.get("errors", []) if isinstance(result, dict) else []
                notice = result.get("notice") if isinstance(result, dict) else None

                if isinstance(result, dict) and "count" not in result:
                    items = result.get("items", [])
                    common_logs = result.get("common_logs", [])
                    count = len(items) if isinstance(items, list) else 0
                    if not count and isinstance(common_logs, list):
                        count = len(common_logs)

                if notice and not count and not errors:
                    status = "not_available"
                elif errors:
                    status = "partial" if count else "failed"
                elif isinstance(result, dict) and result.get("collection_complete") is False:
                    status = "partial" if count else "failed"
                else:
                    status = "complete"

            events.append({
                "timestamp": utc_now(),
                "event": label,
                "source": f"live_artifacts.{key}",
                "timestamp_type": "tool_execution_time",
                "count": count,
                "status": status,
            })

        findings["live_artifacts"] = live_artifacts

    if args.scan:
        findings["file_triage"] = scan_directory(args.scan)
        events.append({
            "timestamp": utc_now(),
            "event": "Inventaris dan pemeriksaan file selesai",
            "source": "file_triage",
            "timestamp_type": "tool_execution_time",
        })

        if args.yara_rules:
            findings["yara"] = scan_with_yara(
                args.scan,
                args.yara_rules,
            )
            events.append({
                "timestamp": utc_now(),
                "event": "Pemindaian YARA selesai",
                "source": "yara",
                "timestamp_type": "tool_execution_time",
            })

    if not findings:
        raise SystemExit(
            "Select at least one action: --collect-live or --scan PATH"
        )

    # Simpan hasil timeline yang berasal dari tahap yang benar-benar dijalankan.
    timeline_result = build_timeline(events)
    findings["timeline"] = timeline_result

    manifest = build_manifest(
        args.case_id,
        args.operator,
        findings,
    )

    if args.encrypt:
        password = getpass.getpass("Report encryption password: ")

        if len(password) < 12:
            raise SystemExit(
                "Use a password/passphrase of at least 12 characters."
            )

        write_encrypted_json(
            manifest,
            str(output / "report.json.fernet"),
            password,
        )
        write_pdf(
            manifest,
            str(output / "report.pdf"),
            password,
        )

        # Jangan membuat timeline.json plaintext dalam mode terenkripsi.
        files = ["report.json.fernet", "report.pdf"]
        html_generated = False

    else:
        write_json(manifest, str(output / "report.json"))

        write_timeline_json(
            events,
            str(output / "timeline.json"),
        )

        write_pdf(manifest, str(output / "report.pdf"))
        write_html_report(manifest, str(output / "report.html"))

        files = [
            "report.json",
            "report.pdf",
            "report.html",
            "timeline.json",
        ]
        html_generated = True

    print(
        json.dumps(
            {
                "status": "complete",
                "case_id": args.case_id,
                "output_directory": str(output.resolve()),
                "files": files,
                "timeline_events": len(events),
                "encrypted": args.encrypt,
                "html_report_generated": html_generated,
                "note": (
                    "Timeline timestamps record when SentinelTriage "
                    "completed each stage, not the original time of "
                    "the underlying evidence. HTML and plaintext timeline "
                    "are omitted in encrypted mode."
                ),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
