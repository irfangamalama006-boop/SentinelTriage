
"""Read-only collection of basic host artifacts."""
from __future__ import annotations

import platform
import socket
import subprocess
from datetime import datetime, timezone


def utc_now() -> str:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def collect_host_info() -> dict:
    """Collect basic host and OS metadata."""
    return {
        "collected_at_utc": utc_now(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
    }


def collect_processes() -> dict:
    """Collect accessible processes and record errors."""
    try:
        import psutil
    except ImportError:
        return {
            "items": [],
            "errors": [{"error": "psutil is not installed"}],
            "count": 0,
            "collection_complete": False,
        }

    rows, errors = [], []

    for proc in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "username", "create_time", "status"]
    ):
        try:
            item = proc.info.copy()
            created = item.get("create_time")

            if created:
                item["create_time_utc"] = datetime.fromtimestamp(
                    created, timezone.utc
                ).isoformat()
                item.pop("create_time", None)

            rows.append(item)

        except (
            psutil.AccessDenied,
            psutil.NoSuchProcess,
            psutil.ZombieProcess,
            OSError,
        ) as exc:
            errors.append({
                "pid": getattr(proc, "pid", None),
                "error": type(exc).__name__,
            })

    return {
        "items": rows,
        "errors": errors,
        "count": len(rows),
        "collection_complete": not errors,
    }


def _collect_network_lsof() -> dict:
    """Collect visible network sockets using macOS lsof field output."""
    try:
        result = subprocess.run(
            ["/usr/sbin/lsof", "-nP", "-F0pcfPnT", "-i"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "source": "lsof",
            "items": [],
            "errors": [{
                "error": type(exc).__name__,
                "detail": str(exc),
            }],
            "count": 0,
            "collection_complete": False,
        }

    if result.returncode not in (0, 1):
        return {
            "source": "lsof",
            "items": [],
            "errors": [{
                "error": "command_failed",
                "detail": result.stderr.strip()
                or f"Exit code {result.returncode}",
            }],
            "count": 0,
            "collection_complete": False,
        }

    rows = []
    errors = []
    process = {"pid": None, "name": None}
    file_record = {}

    def save_record() -> None:
        """Save one network file descriptor when it has an endpoint."""
        if not file_record.get("n"):
            return

        endpoint = file_record["n"]
        local_address = endpoint
        remote_address = None

        if "->" in endpoint:
            local_address, remote_address = endpoint.split("->", 1)

        try:
            pid = int(process["pid"]) if process["pid"] else None
        except (TypeError, ValueError):
            pid = None

        rows.append({
            "process": process["name"],
            "pid": pid,
            "family": file_record.get("P"),
            "type": file_record.get("P"),
            "local_address": local_address or None,
            "remote_address": remote_address,
            "status": file_record.get("ST"),
            "fd": file_record.get("fd"),
        })

    # With -F0, fields are NUL-delimited; newline separates records.
    for line in result.stdout.splitlines():
        for field in line.split("\0"):
            if not field:
                continue

            tag, value = field[0], field[1:]

            if tag == "p":
                save_record()
                process = {"pid": value, "name": None}
                file_record = {}

            elif tag == "c":
                process["name"] = value

            elif tag == "f":
                save_record()
                file_record = {"fd": value}

            elif tag == "P":
                file_record["P"] = value

            elif tag == "n":
                file_record["n"] = value

            elif tag == "T" and "=" in value:
                key, val = value.split("=", 1)
                if key == "ST":
                    file_record["ST"] = val

    save_record()

    if result.stderr.strip():
        errors.append({
            "error": "lsof_notice",
            "detail": result.stderr.strip(),
        })

    return {
        "source": "lsof",
        "items": rows,
        "errors": errors,
        "count": len(rows),
        "collection_complete": False,
        "collection_note": (
            "lsof results may be incomplete and only include sockets "
            "visible to the current user. They are not a complete "
            "system-wide network capture."
        ),
    }


def collect_network() -> dict:
    """Collect network connections, falling back to lsof on macOS."""
    try:
        import psutil
    except ImportError:
        psutil = None

    if psutil is not None:
        try:
            connections = psutil.net_connections(kind="inet")
            rows = []

            for conn in connections:
                rows.append({
                    "process": None,
                    "pid": conn.pid,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local_address": (
                        f"{conn.laddr.ip}:{conn.laddr.port}"
                        if conn.laddr else None
                    ),
                    "remote_address": (
                        f"{conn.raddr.ip}:{conn.raddr.port}"
                        if conn.raddr else None
                    ),
                    "status": conn.status,
                })

            return {
                "source": "psutil",
                "items": rows,
                "errors": [],
                "count": len(rows),
                "collection_complete": True,
            }

        except (psutil.AccessDenied, OSError) as exc:
            fallback = (
                _collect_network_lsof()
                if platform.system() == "Darwin"
                else {
                    "source": None,
                    "items": [],
                    "errors": [],
                    "count": 0,
                    "collection_complete": False,
                }
            )
            fallback["errors"].insert(0, {
                "source": "psutil",
                "error": type(exc).__name__,
                "detail": str(exc),
            })
            return fallback

    if platform.system() == "Darwin":
        return _collect_network_lsof()

    return {
        "source": None,
        "items": [],
        "errors": [{"error": "psutil is not installed"}],
        "count": 0,
        "collection_complete": False,
    }


def collect_windows_registry() -> dict:
    """Read selected Windows Run keys without modifying registry values."""
    if platform.system() != "Windows":
        return {
            "notice": "Windows registry collection is available only on Windows.",
            "items": [],
        }

    try:
        import winreg
    except ImportError:
        return {"error": "winreg is unavailable", "items": []}

    locations = [
        (
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ),
    ]

    items, errors = [], []

    for hive, subkey in locations:
        try:
            with winreg.OpenKey(
                hive, subkey, 0, winreg.KEY_READ
            ) as key:
                index = 0

                while True:
                    try:
                        name, value, _kind = winreg.EnumValue(key, index)
                        items.append({
                            "hive": str(hive),
                            "key": subkey,
                            "name": name,
                            "value": str(value),
                        })
                        index += 1
                    except OSError:
                        break

        except OSError as exc:
            errors.append({
                "key": subkey,
                "error": str(exc),
            })

    return {
        "items": items,
        "errors": errors,
        "count": len(items),
    }


def collect_event_log_metadata() -> dict:
    """Provide Windows Event Log guidance without modifying logs."""
    if platform.system() != "Windows":
        return {
            "notice": "Windows Event Logs are available only on Windows."
        }

    return {
        "notice": (
            "Acquire EVTX files using an approved evidence-preservation workflow."
        ),
        "common_logs": [
            "System",
            "Security",
            "Application",
            "Microsoft-Windows-PowerShell/Operational",
        ],
        "note": "This module does not clear logs or change audit settings.",
    }


def collect_live_artifacts() -> dict:
    """Collect supported live artifacts into one JSON-compatible object."""
    return {
        "host": collect_host_info(),
        "processes": collect_processes(),
        "network": collect_network(),
        "registry_run_keys": collect_windows_registry(),
        "event_logs": collect_event_log_metadata(),
    }
