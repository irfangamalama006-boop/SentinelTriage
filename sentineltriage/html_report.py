
"""Standalone interactive HTML dashboard for SentinelTriage."""

import html
import json
from pathlib import Path

from .network_analysis import analyze_network
from .process_analysis import analyze_processes


def _e(value):
    """Escape data before inserting it into HTML."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    return html.escape(str(value), quote=True)


def _table(headers, rows, empty_message):
    header_html = "".join(f"<th>{_e(h)}</th>" for h in headers)

    if not rows:
        return f'<p class="empty">{_e(empty_message)}</p>'

    body = []
    for row in rows:
        cells = "".join(f"<td>{_e(cell)}</td>" for cell in row)
        body.append(f"<tr>{cells}</tr>")

    return (
        '<div class="table-wrap"><table class="data-table">'
        f"<thead><tr>{header_html}</tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table></div>"
    )


def _get_indicators(files):
    result = []
    for item in files:
        if not isinstance(item, dict):
            continue

        indicators = item.get("indicators", [])
        if not isinstance(indicators, list):
            continue

        for indicator in indicators:
            if isinstance(indicator, dict):
                result.append((
                    item.get("path", ""),
                    indicator.get("type", indicator.get("name", "Indikator")),
                    indicator.get(
                        "description",
                        indicator.get("details", indicator),
                    ),
                ))
            else:
                result.append((
                    item.get("path", ""),
                    "Indikator",
                    indicator,
                ))

    return result


def _get_errors(findings):
    result = []

    for module_name, module in findings.items():
        if not isinstance(module, dict):
            continue

        errors = module.get("errors", [])
        if isinstance(errors, list):
            for error in errors:
                result.append((module_name, error))
        elif errors:
            result.append((module_name, errors))

    return result


def write_html_report(manifest, output_path):
    """Generate a self-contained HTML dashboard."""

    # Baca timeline.json dari folder output laporan, jika tersedia.
    timeline_result = {}
    timeline_path = Path(output_path).parent / "timeline.json"

    try:
        if timeline_path.is_file():
            loaded = json.loads(
                timeline_path.read_text(encoding="utf-8")
            )
            if isinstance(loaded, dict):
                timeline_result = loaded
    except (OSError, json.JSONDecodeError):
        timeline_result = {}

    timeline_events = timeline_result.get("timeline", [])
    if not isinstance(timeline_events, list):
        timeline_events = []

    timeline_rows = []
    status_labels = {
        "complete": "Berhasil",
        "partial": "Parsial",
        "failed": "Gagal",
        "not_available": "Tidak tersedia",
    }

    for event in timeline_events:
        if isinstance(event, dict):
            status = event.get("status")
            count = event.get("count")

            timeline_rows.append((
                event.get("timestamp_utc", event.get("timestamp", "")),
                event.get("event", "Peristiwa"),
                event.get("source", "Tidak diketahui"),
                status_labels.get(status, status or "-"),
                str(count) if count is not None else "-",
            ))

    unplaced = timeline_result.get("unplaced_events", [])
    if not isinstance(unplaced, list):
        unplaced = []

    unplaced_rows = []
    for item in unplaced:
        if isinstance(item, dict):
            detail = item.get("event", {})
            if isinstance(detail, dict):
                detail = detail.get("event", detail)
            unplaced_rows.append((
                item.get("reason", "Timestamp tidak valid"),
                detail,
            ))


    findings = manifest.get("findings") or {}
    if not isinstance(findings, dict):
        findings = {}

    file_data = findings.get("file_triage") or {}
    yara_data = findings.get("yara") or {}
    live_data = findings.get("live_artifacts") or {}

    if not isinstance(file_data, dict):
        file_data = {}
    if not isinstance(yara_data, dict):
        yara_data = {}
    if not isinstance(live_data, dict):
        live_data = {}

    files = file_data.get("files", [])
    if not isinstance(files, list):
        files = []
    files = [item for item in files if isinstance(item, dict)]

    matches = yara_data.get("matches", [])
    if not isinstance(matches, list):
        matches = []
    matches = [item for item in matches if isinstance(item, dict)]

    indicators = _get_indicators(files)
    errors = _get_errors(findings)

    inspected = file_data.get("files_inspected", len(files))
    scanned = yara_data.get("scanned_files", 0)

    if not isinstance(inspected, (int, float)):
        inspected = len(files)
    if not isinstance(scanned, (int, float)):
        scanned = 0

    case_id = _e(manifest.get("case_id", "N/A"))
    operator = _e(manifest.get("operator", "N/A"))
    created = _e(manifest.get("created_at_utc", "N/A"))
    mode = _e(manifest.get("collection_mode", "N/A"))
    schema = _e(manifest.get("schema", "N/A"))

    file_rows = [
        (
            item.get("path", ""),
            item.get(
                "size_bytes",
                item.get("size", item.get("file_size", "")),
            ),
            item.get("sha256", ""),
        )
        for item in files
    ]

    yara_rows = []
    for match in matches:
        tags = match.get("tags", [])
        if isinstance(tags, list):
            tags = ", ".join(map(str, tags))

        yara_rows.append((
            match.get("path", match.get("file", "")),
            match.get("rule", match.get("rule_name", "")),
            tags,
            match.get("meta", {}),
        ))

    error_rows = [(module, error) for module, error in errors]

    limitations = manifest.get("limitations", [])
    if not isinstance(limitations, list):
        limitations = [limitations] if limitations else []

    limitation_html = "".join(
        f"<li>{_e(item)}</li>" for item in limitations
    )
    if not limitation_html:
        limitation_html = "<li>Tidak ada catatan batasan.</li>"

    max_count = max(int(inspected), int(scanned), len(matches), 1)
    file_width = min(100, int(int(inspected) / max_count * 100))
    scan_width = min(100, int(int(scanned) / max_count * 100))
    yara_width = min(100, int(len(matches) / max_count * 100))

    live_json = _e(json.dumps(
        live_data, indent=2, ensure_ascii=False, default=str
    ))

    network_data = live_data.get("network") or {}
    if not isinstance(network_data, dict):
        network_data = {}

    network_items = network_data.get("items", [])
    if not isinstance(network_items, list):
        network_items = []
    network_items = [
        item for item in network_items
        if isinstance(item, dict)
    ]

    network_errors = network_data.get("errors", [])
    if not isinstance(network_errors, list):
        network_errors = []

    established = sum(
        str(item.get("status") or "").upper() == "ESTABLISHED"
        for item in network_items
    )
    listening = sum(
        str(item.get("status") or "").upper() == "LISTEN"
        for item in network_items
    )

    network_source_raw = str(network_data.get("source") or "N/A")
    network_source = _e(network_source_raw)
    network_count = len(network_items)

    # Pengelompokan baris berdasarkan atribut yang tersedia.
    # Ini bukan bukti identitas koneksi yang sebenarnya.
    connection_keys = set()
    for item in network_items:
        key = (
            str(item.get("process") or ""),
            str(item.get("pid") or ""),
            str(item.get("type") or item.get("family") or ""),
            str(item.get("local_address") or ""),
            str(item.get("remote_address") or ""),
            str(item.get("status") or "").upper(),
        )
        connection_keys.add(key)

    unique_connection_count = len(connection_keys)
    duplicate_count = max(0, network_count - unique_connection_count)

    network_note_raw = (
        network_data.get("collection_note")
        or network_data.get("note")
        or network_data.get("message")
        or ""
    )
    network_note = _e(str(network_note_raw))

    # lsof tidak menjamin cakupan semua proses pada sistem.
    network_complete = (
        network_data.get("collection_complete") is True
        and network_source_raw.lower() != "lsof"
        and len(network_errors) == 0
    )
    network_collected = (
        "live_artifacts" in findings
        and isinstance(findings.get("live_artifacts"), dict)
        and isinstance(live_data.get("network"), dict)
        and bool(network_data)
    )

    if not network_collected:
        network_status = "Tidak dijalankan"
    elif network_complete:
        network_status = "Lengkap menurut status kolektor"
    elif network_count == 0 and not network_errors:
        network_status = "Dijalankan, tetapi tidak ada data socket"
    else:
        network_status = "Tidak lengkap atau belum terverifikasi"

    network_status = _e(network_status)

    # Penilaian awal berbasis aturan; tidak menyatakan koneksi sebagai malware.
    network_assessment = (
        analyze_network(network_data) if network_collected
        else analyze_network({})
    )

    assessment_rows = [
        (
            item.get("process"),
            item.get("pid") if item.get("pid") is not None else "N/A",
            item.get("protocol") or "Tidak diketahui",
            item.get("local_address") or "N/A",
            item.get("remote_address") or "N/A",
            item.get("status") or "N/A",
            item.get("remote_scope"),
            "; ".join(item.get("reasons", [])),
        )
        for item in network_assessment["review_items"]
    ]

    scope_labels = {
        "public": "Publik",
        "private": "Private",
        "loopback": "Loopback",
        "link_local": "Link-local",
        "multicast": "Multicast",
        "unknown": "Tidak dikenal",
        "none": "Tidak ada alamat remote",
    }

    assessment_scope_summary = " · ".join(
        f"{scope_labels.get(key, key)}: {value}"
        for key, value in network_assessment["remote_scope_counts"].items()
        if value
    ) or "Belum ada data alamat remote"

    assessment_total = (
        network_assessment["total_items"] if network_collected else "—"
    )
    assessment_unique_total = (
        network_assessment["unique_count"] if network_collected else "—"
    )
    assessment_review = (
        network_assessment["review_count"] if network_collected else "—"
    )
    assessment_raw_review = (
        network_assessment["raw_review_count"] if network_collected else "—"
    )
    assessment_info = (
        network_assessment["informational_count"] if network_collected else "—"
    )
    assessment_note = _e(network_assessment["note"])

    # Penilaian proses berdasarkan metadata yang dikumpulkan Live Triage.
    process_data = live_data.get("processes", {})
    if not isinstance(process_data, dict):
        process_data = {}
    process_collected = isinstance(live_data.get("processes"), dict)
    process_assessment = analyze_processes(process_data)
    process_total = (
        process_assessment["total_items"] if process_collected else "—"
    )
    process_review = (
        process_assessment["review_count"] if process_collected else "—"
    )
    process_info = (
        process_assessment["informational_count"] if process_collected else "—"
    )
    process_error_count = (
        process_assessment["error_count"] if process_collected else "—"
    )
    process_rows = [
        (
            item["name"],
            item["pid"] if item["pid"] is not None else "N/A",
            item["exe"],
            item["status"],
            "; ".join(item["reasons"]),
        )
        for item in process_assessment["review_items"][:100]
    ]
    process_note = _e(process_assessment["note"])
    process_notice = (
        ""
        if process_collected
        else '<p class="notice">Koleksi proses tidak dijalankan untuk kasus ini.</p>'
    )

    network_count_display = network_count if network_collected else "—"
    unique_count_display = unique_connection_count if network_collected else "—"
    duplicate_count_display = duplicate_count if network_collected else "—"
    established_display = established if network_collected else "—"
    listening_display = listening if network_collected else "—"
    network_errors_display = len(network_errors) if network_collected else "—"

    network_rows = [
        (
            item.get("process") or "N/A",
            item.get("pid") if item.get("pid") is not None else "N/A",
            item.get("local_address") or "N/A",
            item.get("remote_address") or "N/A",
            item.get("status") or "N/A",
        )
        for item in network_items
    ]

    if not network_collected:
        network_notice = (
            '<p class="notice">Koleksi jaringan tidak dijalankan '
            'untuk kasus ini. Tidak ada kesimpulan yang dapat dibuat '
            'mengenai koneksi jaringan dari bagian ini.</p>'
        )
    elif network_note:
        network_notice = (
            f'<p class="notice">{network_note}</p>'
        )
    elif not network_complete:
        network_notice = (
            '<p class="notice">Koleksi jaringan tidak lengkap '
            'atau belum terverifikasi. Hasil dapat dibatasi oleh '
            'izin akses dan tidak mewakili rekaman jaringan penuh.</p>'
        )
    else:
        network_notice = ""

    network_error_rows = [
        (
            error.get("source") or "N/A",
            error.get("error") or "Error",
            error.get("detail") or "",
        )
        if isinstance(error, dict)
        else ("N/A", "Error", str(error))
        for error in network_errors
    ]

    document = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelTriage - {case_id}</title>
<style>
:root {{
  --bg:#f3f6fb;
  --panel:#ffffff;
  --text:#172033;
  --muted:#65718a;
  --line:#e0e6f0;
  --accent:#3157d5;
  --soft:#eaf0ff;
}}
body.dark {{
  --bg:#101827;
  --panel:#182235;
  --text:#e7edf8;
  --muted:#a7b3c8;
  --line:#2d3a50;
  --accent:#91aaff;
  --soft:#263656;
}}
* {{box-sizing:border-box}}
body {{
  margin:0;
  background:var(--bg);
  color:var(--text);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}}
header {{
  background:#111d38;
  color:white;
  padding:28px max(20px,calc((100% - 1180px)/2));
  border-bottom:4px solid #5278f0;
}}
header h1 {{margin:0;font-size:28px}}
header p {{margin:6px 0 0;color:#cbd6f2}}
main {{max-width:1180px;margin:24px auto;padding:0 18px 40px}}
.toolbar {{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}}
input,button {{
  font:inherit;border:1px solid var(--line);
  border-radius:9px;padding:10px 13px;
}}
input {{
  background:var(--panel);color:var(--text);
  flex:1;min-width:220px;
}}
button {{background:var(--panel);color:var(--text);cursor:pointer}}
button:hover {{border-color:var(--accent)}}
.meta,.panel,.metric {{
  background:var(--panel);border:1px solid var(--line);
  border-radius:14px;box-shadow:0 4px 16px #10204008;
}}
.meta {{
  padding:18px 20px;display:grid;
  grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;
}}
.meta span {{
  display:block;color:var(--muted);font-size:12px;
  text-transform:uppercase;letter-spacing:.5px;
}}
.meta strong {{display:block;margin-top:4px;overflow-wrap:anywhere}}
.metrics {{
  display:grid;grid-template-columns:repeat(4,minmax(0,1fr));
  gap:14px;margin:18px 0;
}}
.metric {{padding:18px}}
.label {{color:var(--muted);font-size:13px}}
.number {{font-size:30px;font-weight:750;margin:8px 0}}
.hint {{font-size:12px;color:var(--muted)}}
.bar {{
  height:6px;background:var(--line);
  border-radius:9px;overflow:hidden;margin-top:12px;
}}
.bar span {{display:block;height:100%;background:var(--accent)}}
.panel {{padding:20px;margin:16px 0;min-width:0}}
.panel h2 {{font-size:18px;margin:0 0 13px}}
.panel p {{color:var(--muted)}}
.table-wrap {{width:100%;overflow-x:auto}}
table {{width:100%;border-collapse:collapse;font-size:13px}}
th,td {{
  padding:11px 12px;text-align:left;
  border-bottom:1px solid var(--line);
  vertical-align:top;overflow-wrap:anywhere;
}}
th {{background:var(--soft);font-weight:650}}
td {{max-width:420px}}
.empty {{color:var(--muted);padding:10px 0}}
.pill {{
  display:inline-block;border-radius:999px;
  padding:3px 9px;font-size:12px;background:var(--soft);
}}
details {{border:1px solid var(--line);border-radius:10px;padding:12px 14px}}
summary {{cursor:pointer;font-weight:650}}
pre {{
  white-space:pre-wrap;overflow-wrap:anywhere;
  max-height:440px;overflow:auto;font-size:12px;
}}
.notice {{
  border-left:4px solid #c17a12;
  padding:12px 15px;background:var(--panel);border-radius:6px;
}}
footer {{text-align:center;color:var(--muted);font-size:12px;padding:22px}}
@media(max-width:760px) {{
  .meta,.metrics {{grid-template-columns:repeat(2,minmax(0,1fr))}}
  header h1 {{font-size:23px}}
}}
@media(max-width:440px) {{
  .meta,.metrics {{grid-template-columns:1fr}}
}}
@media print {{
  body {{background:white;color:#111}}
  header {{background:white;color:#111;border-bottom:2px solid #333}}
  header p {{color:#444}}
  main {{max-width:none}}
  .toolbar {{display:none}}
  .panel,.metric,.meta {{box-shadow:none;break-inside:avoid}}
}}
</style>
</head>
<body>
<header>
  <h1>SentinelTriage</h1>
  <p>Digital Forensics &amp; Malware Triage — Dashboard Pemeriksaan</p>
</header>
<main>
  <div class="toolbar">
    <input id="tableSearch" type="search"
      placeholder="Cari file, hash, aturan, atau temuan...">
    <button id="themeToggle" type="button">Mode gelap</button>
    <button type="button" onclick="window.print()">Cetak / Simpan PDF</button>
  </div>

  <section class="meta">
    <div><span>Case ID</span><strong>{case_id}</strong></div>
    <div><span>Analis / Operator</span><strong>{operator}</strong></div>
    <div><span>Waktu UTC</span><strong>{created}</strong></div>
    <div><span>Mode koleksi</span><strong>{mode}</strong></div>
  </section>

  <section class="metrics">
    <article class="metric">
      <div class="label">File diperiksa</div>
      <div class="number">{int(inspected)}</div>
      <div class="hint">Inventaris file</div>
      <div class="bar"><span style="width:{file_width}%"></span></div>
    </article>
    <article class="metric">
      <div class="label">File dipindai YARA</div>
      <div class="number">{int(scanned)}</div>
      <div class="hint">Cakupan pemindaian</div>
      <div class="bar"><span style="width:{scan_width}%"></span></div>
    </article>
    <article class="metric">
      <div class="label">Kecocokan YARA</div>
      <div class="number">{len(matches)}</div>
      <div class="hint">Perlu verifikasi analis</div>
      <div class="bar"><span style="width:{yara_width}%"></span></div>
    </article>
    <article class="metric">
      <div class="label">Indikator / Kesalahan</div>
      <div class="number">{len(indicators)} / {len(errors)}</div>
      <div class="hint">Indikator file dan error koleksi</div>
    </article>
  </section>

  <section class="panel">
    <h2>Inventaris dan integritas file</h2>
    <p>Gunakan SHA-256 untuk membantu memverifikasi integritas berkas.</p>
    {_table(["Path file", "Ukuran (byte)", "SHA-256"], file_rows, "Tidak ada data file.")}
  </section>

  <section class="panel">
    <h2>Hasil pemindaian YARA</h2>
    <p>Kecocokan aturan bukan bukti final bahwa file berbahaya.</p>
    {_table(["Path file", "Nama aturan", "Tags", "Metadata"], yara_rows, "Tidak ada kecocokan YARA.")}
  </section>

  <section class="panel">
    <h2>Timeline investigasi</h2>
    <p>Urutan peristiwa berdasarkan timestamp UTC dari timeline.json.</p>
    {_table(["Waktu UTC", "Peristiwa", "Sumber", "Status", "Jumlah"], timeline_rows, "Belum ada data timeline.")}
    <h3>Peristiwa tanpa waktu valid</h3>
    {_table(["Alasan", "Detail peristiwa"], unplaced_rows, "Tidak ada peristiwa yang perlu ditinjau.")}
  </section>

  <section class="panel">
    <h2>Indikator file</h2>
    {_table(["Path file", "Jenis indikator", "Detail"], indicators, "Tidak ada indikator file yang dilaporkan.")}
  </section>

  <section class="panel">
    <h2>Kesalahan analisis</h2>
    {_table(["Modul", "Pesan"], error_rows, "Tidak ada kesalahan yang dilaporkan.")}
  </section>

  <section class="panel">
    <h2>Ringkasan koneksi jaringan</h2>
    <p>Sumber koleksi: <strong>{network_source}</strong></p>
    <p>Status koleksi: <strong>{network_status}</strong></p>

    <div class="cards">
      <article class="card">
        <div class="label">Baris socket mentah</div>
        <div class="number">{network_count_display}</div>
      </article>
      <article class="card">
        <div class="label">Kombinasi koneksi unik</div>
        <div class="number">{unique_count_display}</div>
      </article>
      <article class="card">
        <div class="label">Baris berulang berdasarkan kunci</div>
        <div class="number">{duplicate_count_display}</div>
      </article>
      <article class="card">
        <div class="label">TCP Established</div>
        <div class="number">{established_display}</div>
      </article>
      <article class="card">
        <div class="label">TCP Listen</div>
        <div class="number">{listening_display}</div>
      </article>
      <article class="card">
        <div class="label">Kesalahan koleksi</div>
        <div class="number">{network_errors_display}</div>
      </article>
    </div>

    {network_notice}

    <h3>Penilaian awal koneksi jaringan</h3>
    <div class="cards">
      <article class="card">
        <div class="label">Koneksi dianalisis</div>
        <div class="number">{assessment_total}</div>
      </article>
      <article class="card">
        <div class="label">Koneksi unik dianalisis</div>
        <div class="number">{assessment_unique_total}</div>
      </article>
      <article class="card">
        <div class="label">Perlu ditinjau (unik)</div>
        <div class="number">{assessment_review}</div>
      </article>
      <article class="card">
        <div class="label">Baris mentah perlu ditinjau</div>
        <div class="number">{assessment_raw_review}</div>
      </article>
      <article class="card">
        <div class="label">Informasi</div>
        <div class="number">{assessment_info}</div>
      </article>
    </div>

    <p><strong>Kategori alamat remote:</strong>
      {_e(assessment_scope_summary)}
    </p>
    <p class="notice">{assessment_note}</p>

    <h3>Daftar koneksi yang perlu ditinjau</h3>
    {_table(
        [
            "Proses", "PID", "Protokol", "Alamat lokal",
            "Alamat remote", "Status", "Kategori",
            "Alasan pemeriksaan"
        ],
        assessment_rows,
        "Tidak ada koneksi yang ditandai perlu ditinjau berdasarkan aturan saat ini."
    )}

    <p>
      Status perlu ditinjau bukan berarti koneksi berbahaya. Analis perlu
      memeriksa konteks proses, kebutuhan layanan, dan bukti pendukung.
    </p>

    <p>
      Kombinasi unik dihitung dari proses, PID, protokol atau keluarga,
      alamat lokal, alamat remote, dan status. Baris mentah tetap
      dipertahankan. Pengelompokan ini bukan verifikasi identitas koneksi.
    </p>

    <h3>Detail socket</h3>
    {_table(["Proses", "PID", "Alamat lokal", "Alamat remote", "Status"],
            network_rows, "Tidak ada data socket.")}

    <h3>Kesalahan koleksi jaringan</h3>
    {_table(["Sumber", "Jenis kesalahan", "Detail"],
            network_error_rows, "Tidak ada kesalahan yang dilaporkan.")}
  </section>

  <section class="panel">
    <h2>Penilaian awal proses (Process Risk Assessment)</h2>
    <p>Analisis metadata proses yang dikumpulkan dari perangkat.</p>
    {process_notice}
    <div class="cards">
      <article class="card">
        <div class="label">Proses dianalisis</div>
        <div class="number">{process_total}</div>
      </article>
      <article class="card">
        <div class="label">Perlu ditinjau</div>
        <div class="number">{process_review}</div>
      </article>
      <article class="card">
        <div class="label">Informasi</div>
        <div class="number">{process_info}</div>
      </article>
      <article class="card">
        <div class="label">Kesalahan koleksi</div>
        <div class="number">{process_error_count}</div>
      </article>
    </div>
    <p class="notice">{process_note}</p>
    <h3>Daftar proses yang perlu ditinjau</h3>
    {_table(
        ["Proses", "PID", "Lokasi executable", "Status", "Alasan pemeriksaan"],
        process_rows,
        "Tidak ada proses yang ditandai perlu ditinjau berdasarkan aturan saat ini."
    )}
    <p>
      Status perlu ditinjau bukan berarti proses berbahaya. Verifikasi nama,
      lokasi file, pengguna, waktu mulai, dan konteks aktivitas sebelum mengambil
      kesimpulan. Maksimal 100 baris ditampilkan pada tabel ini.
    </p>
  </section>

  <section class="panel">
    <h2>Artefak sistem langsung</h2>
    <details>
      <summary>Lihat data artefak sistem (JSON)</summary>
      <pre>{live_json}</pre>
    </details>
  </section>

  <section class="panel">
    <h2>Batasan pemeriksaan</h2>
    <ul>{limitation_html}</ul>
    <div class="notice">
      Hasil ini merupakan bantuan triase awal. Validasi temuan dengan bukti
      pendukung, pertahankan bukti asli, dan dokumentasikan tindakan pemeriksaan.
    </div>
  </section>

  <section class="panel">
    <h2>Informasi laporan</h2>
    <p>Schema: <span class="pill">{schema}</span></p>
    <p>Dashboard ini dibuat secara lokal oleh SentinelTriage.</p>
  </section>
</main>
<footer>SentinelTriage · Laporan lokal · Distribusikan hanya kepada pihak berwenang</footer>

<script>
const search = document.getElementById("tableSearch");
search.addEventListener("input", function () {{
  const query = this.value.toLowerCase();
  document.querySelectorAll(".data-table tbody tr").forEach(function (row) {{
    row.hidden = !row.textContent.toLowerCase().includes(query);
  }});
}});
document.getElementById("themeToggle").addEventListener("click", function () {{
  document.body.classList.toggle("dark");
  this.textContent = document.body.classList.contains("dark")
    ? "Mode terang" : "Mode gelap";
}});
</script>
</body>
</html>
"""

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")
    return str(output)
