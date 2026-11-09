"""Rule-based network triage. This module does not block or alter connections."""

import ipaddress


def _extract_host(endpoint):
    """Extract an IP or hostname from an address such as 1.2.3.4:443."""
    if not endpoint:
        return None

    value = str(endpoint).strip()
    if value in ("*", "*:*", "N/A"):
        return None

    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")]

    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]

    if value.count(":") > 1:
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            return value.rsplit(":", 1)[0]

    return value


def _classify_address(endpoint):
    host = _extract_host(endpoint)
    if not host:
        return "none"

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "unknown"

    if address.is_loopback:
        return "loopback"
    if address.is_private:
        return "private"
    if address.is_link_local:
        return "link_local"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified:
        return "unspecified"
    if address.is_global:
        return "public"

    return "unknown"


def _connection_key(item):
    """Build a comparison key; this is not proof of connection identity."""
    return (
        str(item.get("process") or ""),
        str(item.get("pid") or ""),
        str(item.get("type") or item.get("family") or ""),
        str(item.get("local_address") or ""),
        str(item.get("remote_address") or ""),
        str(item.get("status") or "").upper(),
    )


def analyze_network(network_data):
    """Summarize raw sockets and deduplicate review prompts."""
    if not isinstance(network_data, dict):
        network_data = {}

    items = network_data.get("items", [])
    if not isinstance(items, list):
        items = []

    results = []
    scope_counts = {
        "public": 0,
        "private": 0,
        "loopback": 0,
        "link_local": 0,
        "multicast": 0,
        "unspecified": 0,
        "unknown": 0,
        "none": 0,
    }

    for item in items:
        if not isinstance(item, dict):
            continue

        remote_scope = _classify_address(item.get("remote_address"))
        local_scope = _classify_address(item.get("local_address"))

        if remote_scope not in scope_counts:
            remote_scope = "unknown"

        scope_counts[remote_scope] += 1
        status = str(item.get("status") or "").upper()
        local_address = str(item.get("local_address") or "")
        reasons = []

        if status == "LISTEN" and local_address.startswith("*:"):
            reasons.append(
                "Layanan mendengarkan pada semua interface; "
                "periksa apakah akses tersebut memang diperlukan."
            )

        if item.get("remote_address") and remote_scope == "unknown":
            reasons.append(
                "Alamat remote belum dapat diklasifikasikan; "
                "verifikasi format dan identitas endpoint."
            )

        if not item.get("process") or item.get("pid") is None:
            reasons.append(
                "Informasi proses atau PID tidak lengkap; "
                "perlu verifikasi dari sumber lain."
            )

        results.append({
            "process": item.get("process") or "Tidak diketahui",
            "pid": item.get("pid"),
            "protocol": item.get("type") or item.get("family") or "Tidak diketahui",
            "local_address": item.get("local_address"),
            "remote_address": item.get("remote_address"),
            "status": status or "Tidak diketahui",
            "remote_scope": remote_scope,
            "local_scope": local_scope,
            "assessment": "review" if reasons else "informational",
            "reasons": reasons,
        })

    # Baris mentah tetap dipertahankan. Hanya daftar peninjauan
    # yang dikelompokkan berdasarkan kombinasi atribut socket.
    seen_keys = set()
    seen_review_keys = set()
    review_items = []
    unique_count = 0
    raw_review_count = 0

    valid_raw_items = [
        item for item in items if isinstance(item, dict)
    ]

    for raw_item, result in zip(valid_raw_items, results):
        key = _connection_key(raw_item)

        if key not in seen_keys:
            seen_keys.add(key)
            unique_count += 1

        if result["assessment"] == "review":
            raw_review_count += 1

            if key not in seen_review_keys:
                seen_review_keys.add(key)
                review_items.append(result)

    review_count = len(review_items)

    return {
        "source": network_data.get("source"),
        "total_items": len(results),
        "unique_count": unique_count,
        "duplicate_count": max(0, len(results) - unique_count),
        "review_count": review_count,
        "raw_review_count": raw_review_count,
        "duplicate_review_count": max(0, raw_review_count - review_count),
        "informational_count": max(0, unique_count - review_count),
        "remote_scope_counts": scope_counts,
        "review_items": review_items,
        "items": results,
        "note": (
            "Penilaian berbasis metadata socket dan aturan sederhana. "
            "IP publik, port terbuka, atau koneksi aktif bukan bukti "
            "malware. Baris socket mentah dipertahankan, sedangkan "
            "daftar peninjauan dikelompokkan berdasarkan atribut yang tersedia. "
            "Semua hasil memerlukan verifikasi analis."
        ),
    }
