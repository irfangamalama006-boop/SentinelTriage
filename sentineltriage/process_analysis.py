"""Rule-based process triage; findings require analyst verification."""

def analyze_processes(process_data):
    """Identify process metadata that deserves additional human review."""
    if not isinstance(process_data, dict):
        process_data = {}

    raw_items = process_data.get("items", [])
    if not isinstance(raw_items, list):
        raw_items = []

    results = []

    for item in raw_items:
        if not isinstance(item, dict):
            continue

        name = str(item.get("name") or "").strip()
        executable = str(item.get("exe") or "").strip()
        status = str(item.get("status") or "Tidak diketahui").strip()
        pid = item.get("pid")

        reasons = []

        # kernel_task PID 0 adalah proses sistem khusus macOS.
        # Lokasi executable yang tidak tersedia saja bukan alasan
        # untuk menandainya sebagai proses yang perlu ditinjau.
        is_macos_kernel_task = (
            name.lower() == "kernel_task" and pid == 0
        )

        if not name:
            reasons.append(
                "Nama proses tidak tersedia; identitas proses perlu diverifikasi."
            )

        if not executable:
            if not is_macos_kernel_task:
                reasons.append(
                    "Lokasi executable tidak tersedia; periksa melalui sumber sistem lain."
                )
        else:
            normalized = executable.replace("\\\\", "/").lower()
            temporary_prefixes = (
                "/tmp/",
                "/private/tmp/",
                "/var/tmp/",
                "/private/var/tmp/",
                "/private/var/folders/",
            )
            if normalized.startswith(temporary_prefixes):
                reasons.append(
                    "Executable berada di lokasi sementara; verifikasi asal file "
                    "dan alasan proses berjalan dari lokasi tersebut."
                )

        results.append({
            "name": name or "Tidak diketahui",
            "pid": pid,
            "ppid": item.get("ppid"),
            "exe": executable or "Tidak tersedia",
            "username": item.get("username") or "Tidak tersedia",
            "status": status,
            "create_time_utc": item.get("create_time_utc"),
            "assessment": "review" if reasons else "informational",
            "reasons": reasons,
        })

    review_items = [
        item for item in results
        if item["assessment"] == "review"
    ]

    errors = process_data.get("errors", [])
    if not isinstance(errors, list):
        errors = []

    return {
        "total_items": len(results),
        "review_count": len(review_items),
        "informational_count": len(results) - len(review_items),
        "error_count": len(errors),
        "review_items": review_items,
        "items": results,
        "note": (
            "Penilaian menggunakan metadata proses dan aturan sederhana. "
            "Lokasi sementara atau metadata yang tidak lengkap bukan bukti malware. "
            "Proses yang tidak ditandai juga belum tentu aman. "
            "kernel_task PID 0 merupakan proses sistem khusus macOS. "
            "Semua hasil memerlukan verifikasi analis."
        ),
    }
