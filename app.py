from auth_ui import show_auth, show_user_sidebar, api_request
from pathlib import Path
import json
import os
import re
import subprocess
import sys

import streamlit as st
import streamlit.components.v1 as components

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
MAX_UPLOAD = 100 * 1024 * 1024  # 100 MB


st.set_page_config(
    page_title="SentinelTriage",
    page_icon="🛡️",
    layout="wide",
)


def resolve_path(value):
    """Resolve relative paths against the project folder."""
    value = value.strip()
    if not value:
        return None

    path = Path(os.path.expanduser(value))
    if not path.is_absolute():
        path = ROOT / path

    return path.resolve()


def get_cases():
    """Return case folders containing at least one report."""
    cases = []

    if not REPORTS.is_dir():
        return cases

    for folder in sorted(REPORTS.iterdir(), reverse=True):
        if folder.is_dir():
            files = [
                name for name in (
                    "report.html", "report.pdf",
                    "report.json", "timeline.json"
                )
                if (folder / name).is_file()
            ]
            if files:
                cases.append((folder.name, folder, files))

    return cases


def show_report_center():
    st.header("Report Center")
    st.write("Lihat laporan pemeriksaan yang sudah tersimpan.")

    cases = get_cases()

    if not cases:
        st.info("Belum ada laporan. Jalankan pemeriksaan terlebih dahulu.")
        return

    labels = [case[0] for case in cases]
    selected = st.selectbox("Pilih ID kasus", labels)

    folder = REPORTS / selected
    st.caption(f"Lokasi: {folder}")

    html_path = folder / "report.html"
    pdf_path = folder / "report.pdf"
    json_path = folder / "report.json"
    timeline_path = folder / "timeline.json"

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("HTML", "Tersedia" if html_path.is_file() else "—")
    with col2:
        st.metric("PDF", "Tersedia" if pdf_path.is_file() else "—")
    with col3:
        st.metric("JSON", "Tersedia" if json_path.is_file() else "—")

    if html_path.is_file():
        with st.expander("Tampilkan laporan HTML", expanded=True):
            html = html_path.read_text(
                encoding="utf-8", errors="replace"
            )
            components.html(html, height=750, scrolling=True)

        st.download_button(
            "Unduh laporan HTML",
            data=html_path.read_bytes(),
            file_name=f"{selected}_report.html",
            mime="text/html",
            key=f"html_{selected}",
        )

    if pdf_path.is_file():
        st.download_button(
            "Unduh laporan PDF",
            data=pdf_path.read_bytes(),
            file_name=f"{selected}_report.pdf",
            mime="application/pdf",
            key=f"pdf_{selected}",
        )

    if json_path.is_file():
        st.download_button(
            "Unduh laporan JSON",
            data=json_path.read_bytes(),
            file_name=f"{selected}_report.json",
            mime="application/json",
            key=f"json_{selected}",
        )

        with st.expander("Lihat data JSON"):
            try:
                data = json.loads(
                    json_path.read_text(encoding="utf-8")
                )
                st.json(data)
            except (ValueError, OSError) as error:
                st.error(f"JSON tidak dapat dibaca: {error}")

    if timeline_path.is_file():
        st.download_button(
            "Unduh timeline JSON",
            data=timeline_path.read_bytes(),
            file_name=f"{selected}_timeline.json",
            mime="application/json",
            key=f"timeline_{selected}",
        )


def run_triage(case_id, operator, scan_text, yara_text,
               live, uploaded, require_yara=False):
    """Validate inputs and run the existing CLI."""
    case_id = case_id.strip()
    operator = operator.strip()

    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", case_id)
        or case_id in {".", ".."}
    ):
        st.error(
            "ID kasus wajib 1–64 karakter, dimulai dengan huruf "
            "atau angka. Gunakan huruf, angka, titik, _ atau -."
        )
        return

    if not operator:
        st.error("Nama analis wajib diisi.")
        return

    if len(operator) > 120:
        st.error("Nama analis maksimal 120 karakter.")
        return

    scan_path = None
    yara_path = None

    try:
        if scan_text.strip():
            scan_path = resolve_path(scan_text)
            if not scan_path.exists():
                st.error(f"Target tidak ditemukan: {scan_path}")
                return
            if not (scan_path.is_file() or scan_path.is_dir()):
                st.error("Target harus berupa file atau folder.")
                return

        if yara_text.strip():
            yara_path = resolve_path(yara_text)
            if not yara_path.is_file():
                st.error(
                    f"File aturan YARA tidak ditemukan: {yara_path}"
                )
                return

        if uploaded is not None and uploaded.size > MAX_UPLOAD:
            st.error("File unggahan melebihi batas 100 MB.")
            return

        if uploaded is None and scan_path is None and not live:
            st.error("Pilih file/folder atau aktifkan Live Triage.")
            return

        if require_yara and yara_path is None:
            st.error("YARA Scanner membutuhkan file aturan YARA.")
            return

        if require_yara and uploaded is None and scan_path is None:
            st.error("Pilih file/folder yang akan dipindai YARA.")
            return

        output_path = REPORTS / case_id

        # Protect existing case evidence and reports from accidental overwrite.
        if output_path.exists() and any(output_path.iterdir()):
            st.error(
                "Folder kasus ini sudah berisi data. Gunakan ID kasus "
                "baru agar laporan atau bukti sebelumnya tidak tertimpa."
            )
            return

        output_path.mkdir(parents=True, exist_ok=True)

        if uploaded is not None:
            sample_dir = output_path / "_uploaded_samples"
            sample_dir.mkdir(exist_ok=True)

            # Do not trust the uploaded filename as a filesystem path.
            safe_name = Path(uploaded.name).name
            safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", safe_name)
            if not safe_name or safe_name in {".", ".."}:
                safe_name = "uploaded_sample.bin"

            target_file = sample_dir / safe_name
            target_file.write_bytes(uploaded.getvalue())
            scan_path = target_file

        command = [
            sys.executable,
            "-m", "sentineltriage.cli",
            "--case-id", case_id,
            "--operator", operator,
            "--output", str(output_path),
        ]

        if scan_path is not None:
            command.extend(["--scan", str(scan_path)])

        if yara_path is not None:
            command.extend(["--yara-rules", str(yara_path)])

        if live:
            command.append("--collect-live")

        st.subheader("Hasil Proses")
        st.code(" ".join(command), language="bash")

        with st.spinner("Pemeriksaan sedang berjalan..."):
            result = subprocess.run(
                command,
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )

        if result.returncode == 0:
            st.success("CLI selesai tanpa melaporkan kode kegagalan.")
        else:
            st.error(
                f"CLI berakhir dengan kode {result.returncode}. "
                "Periksa pesan diagnostik."
            )

        with st.expander("Keluaran program", expanded=True):
            st.code(result.stdout or "Tidak ada keluaran.")

        with st.expander("Pesan diagnostik"):
            st.code(result.stderr or "Tidak ada pesan diagnostik.")

        st.write(f"Folder kasus: `{output_path}`")

        html_path = output_path / "report.html"
        if html_path.is_file():
            st.success("Laporan HTML berhasil dibuat.")
            with st.expander("Tampilkan laporan HTML", expanded=True):
                components.html(
                    html_path.read_text(
                        encoding="utf-8", errors="replace"
                    ),
                    height=750,
                    scrolling=True,
                )
        else:
            st.warning(
                "Laporan HTML belum ditemukan. Periksa keluaran CLI."
            )

    except subprocess.TimeoutExpired:
        st.error("Pemeriksaan melewati batas waktu 15 menit.")
    except (OSError, ValueError) as error:
        st.error(f"Operasi gagal: {error}")


# ---------------------------------------------------------------------------
# SentinelTriage visual layer
# ---------------------------------------------------------------------------
ASSETS = ROOT / "assets"
LOGO_PATH = ASSETS / "sentineltriage-logo.svg"


def load_logo():
    try:
        return LOGO_PATH.read_text(encoding="utf-8")
    except OSError:
        return ""


def inject_theme():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap');
    :root { --st-bg:#07111f; --st-panel:#0d1a2b; --st-line:#1c3048; --st-blue:#1687e8; --st-cyan:#37c6d0; --st-muted:#8ea3bb; }
    html, body, [class*="css"] { font-family:'DM Sans',sans-serif; }
    .stApp { background: radial-gradient(ellipse at 70% 0%, #102746 0%, #07111f 45%, #050c16 100%); color:#edf4fb; }
    [data-testid="stHeader"] { background:rgba(5,12,22,.88); }
    [data-testid="stSidebar"] { background:#081321; border-right:1px solid #1b3048; }
    [data-testid="stSidebar"] > div { padding-top:1.1rem; }
    [data-testid="stSidebar"] [data-testid="stRadio"] label { padding:.48rem .65rem; border-radius:9px; }
    [data-testid="stSidebar"] [data-testid="stRadio"] label:hover { background:#122944; }
    .block-container { max-width:1500px; padding-top:1.5rem; padding-bottom:2.5rem; }
    h1,h2,h3 { color:#f4f8fd !important; letter-spacing:-.025em; }
    p, label, .stCaption { color:#b7c7d9; }
    div[data-testid="stMetric"] { background:linear-gradient(145deg,#10233a,#0b1727); border:1px solid #203852; border-radius:14px; padding:16px 18px; }
    div[data-testid="stMetric"] label { color:#8fa8c2 !important; }
    div[data-testid="stMetric"] [data-testid="stMetricValue"] { color:#f5f9ff; }
    div[data-testid="stForm"], div[data-testid="stExpander"], div[data-testid="stDataFrame"] { border:1px solid #203852; border-radius:13px; background:rgba(11,24,40,.78); }
    .stButton button, .stDownloadButton button, .stFormSubmitButton button { border-radius:9px; font-weight:600; }
    .stButton button[kind="primary"], .stFormSubmitButton button[kind="primary"] { background:#087bd5; border:1px solid #1687e8; }
    .stTextInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] { background:#0a1727; color:#edf4fb; border-color:#29415b; border-radius:9px; }
    .stTabs [data-baseweb="tab-list"] { gap:8px; }
    .stTabs [data-baseweb="tab"] { background:#10233a; border-radius:8px 8px 0 0; }
    .brand-card { display:flex; align-items:center; gap:13px; padding:7px 4px 19px; border-bottom:1px solid #20344b; margin-bottom:16px; }
    .brand-card img { width:54px; height:54px; }
    .brand-name { font-size:20px; font-weight:700; color:#f4f8fd; line-height:1.15; }
    .brand-name span { color:#3aa0f5; }
    .brand-sub { color:#91a8c0; font-size:11px; margin-top:5px; line-height:1.4; }
    .hero { border:1px solid #1d4770; border-radius:17px; padding:27px 30px; background:linear-gradient(110deg,rgba(12,35,61,.98),rgba(8,22,39,.93)); margin:2px 0 20px; }
    .hero-kicker { color:#45c4d2; font-size:12px; font-weight:700; letter-spacing:.13em; text-transform:uppercase; }
    .hero-title { color:#f5f9ff; font-size:34px; font-weight:700; margin:7px 0 5px; }
    .hero-title span { color:#3c9ff2; }
    .hero-desc { color:#a9bdd2; font-size:14px; }
    .section-label { color:#e8f1fb; font-size:18px; font-weight:700; margin:8px 0 12px; }
    .small-note { color:#8199b3; font-size:12px; }
    [data-testid="stStatusWidget"] { background:#0d1a2b; }
    </style>
    """, unsafe_allow_html=True)


def render_brand():
    logo_svg = load_logo()
    if logo_svg:
        import base64
        encoded = base64.b64encode(logo_svg.encode("utf-8")).decode("ascii")
        logo_src = f"data:image/svg+xml;base64,{encoded}"
        st.sidebar.markdown(
            f'<div class="brand-card"><img src="{logo_src}">'
            '<div><div class="brand-name">Sentinel<span>Triage</span></div>'
            '<div class="brand-sub">DIGITAL FORENSICS<br>&amp; MALWARE TRIAGE</div></div></div>',
            unsafe_allow_html=True
        )
    else:
        st.sidebar.markdown("## SentinelTriage")


def api_headers():
    token = st.session_state.get("auth_token")
    return {"Authorization": f"Bearer {token}"} if token else {}



def show_investigation_workspace():
    st.title("Workspace Investigasi")
    st.caption("Manajemen kasus, pemindaian, dan hasil temuan investigasi.")

    headers = api_headers()

    case_status, case_data = api_request("GET", "/cases", headers=headers)
    scan_status, scans_data = api_request("GET", "/scans/", headers=headers)

    if case_status != 200:
        st.error(f"Gagal mengambil data kasus: {case_data}")
        return

    if scan_status != 200:
        st.error(f"Gagal mengambil data scan: {scans_data}")
        return

    cases = case_data.get("cases", [])
    scans = scans_data if isinstance(scans_data, list) else []

    st.subheader("Ringkasan Investigasi")

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Kasus", len(cases))
    c2.metric("Total Scan", len(scans))

    total_findings = 0
    for scan in scans:
        status, findings = api_request(
            "GET", f"/scans/{scan['id']}/findings", headers=headers
        )
        if status == 200 and isinstance(findings, list):
            total_findings += len(findings)

    c3.metric("Total Findings", total_findings)

    st.divider()
    st.subheader("Buat Kasus Investigasi")

    with st.form("create_investigation_case"):
        title = st.text_input("Nama kasus")
        description = st.text_area("Deskripsi")
        submitted = st.form_submit_button("Buat Kasus")

    if submitted:
        if len(title.strip()) < 3:
            st.warning("Nama kasus minimal 3 karakter.")
        else:
            status, result = api_request(
                "POST",
                "/cases",
                headers=headers,
                json={
                    "title": title.strip(),
                    "description": description.strip() or None
                }
            )

            if status == 201:
                st.success("Kasus berhasil dibuat.")
                st.rerun()
            else:
                st.error(result.get("detail", result))

    st.divider()
    st.subheader("Daftar Kasus")

        
    selected_case_id = None

    if not cases:
        st.info("Belum ada kasus investigasi.")
    else:
        case_rows = [
            {
                "ID": item["id"],
                "Nomor Kasus": item.get("case_number"),
                "Nama Kasus": item.get("title"),
                "Status": item.get("status")
            }
            for item in cases
        ]

        st.dataframe(case_rows, use_container_width=True, hide_index=True)

        case_options = {
            f"#{item['id']} - {item.get('title', 'Kasus')}": item["id"]
            for item in cases
        }

        selected_case = st.selectbox(
            "Pilih kasus",
            list(case_options.keys()),
            key="workspace_selected_case"
        )

        selected_case_id = case_options[selected_case]

        if st.button("Buat Scan untuk Kasus Ini"):
            status, result = api_request(
                "POST",
                "/scans/",
                headers=headers,
                json={"case_id": case_options[selected_case]}
            )

            if status == 201:
                st.success(f"Scan #{result.get('scan_id')} berhasil dibuat.")
                st.rerun()
            else:
                st.error(result.get("detail", result))
    if selected_case_id is not None:
        scans = [
            scan for scan in scans
            if int(scan.get("case_id") or 0) == int(selected_case_id)
        ]
    else:
        scans = []
        
    st.divider()
    st.subheader("Riwayat Pemindaian")

    if not scans:
        st.info("Belum ada riwayat scan.")
        return

    st.dataframe(
        [
            {
                "Scan ID": item.get("id"),
                "Case ID": item.get("case_id"),
                "Status": item.get("status"),
                "Dibuat": str(item.get("created_at") or "-")
            }
            for item in scans
        ],
        use_container_width=True,
        hide_index=True
    )

    scan_options = {
        f"Scan #{item['id']} - Kasus #{item['case_id']}": item
        for item in scans
    }

    selected_scan_label = st.selectbox(
        "Pilih scan",
        list(scan_options.keys()),
        key="workspace_selected_scan"
    )

    selected_scan = scan_options[selected_scan_label]
    scan_id = selected_scan["id"]

    if selected_scan.get("status") in ("pending", "failed"):
        if st.button("Jalankan YARA Scan", type="primary"):
            status, result = api_request(
                "POST",
                f"/scans/{scan_id}/execute",
                headers=headers,
                json={
                    "target_path": "test-data/sampel-aman",
                    "rules_path": "test-data/aturan/aturan-uji.yar"
                }
            )

            if status == 200:
                st.success(
                    f"Scan selesai. Total temuan: {result.get('total_findings', 0)}"
                )
                st.rerun()
            else:
                st.error(result.get("detail", result))

    st.markdown("#### Hasil Temuan (Findings)")

    status, findings = api_request(
        "GET",
        f"/scans/{scan_id}/findings",
        headers=headers
    )

    if status == 200 and findings:
        for item in findings:
            finding_id = item.get("id")

            st.markdown(f"### #{finding_id} - {item.get('title', 'Temuan')}")

            st.write("**Lokasi file:**")
            st.code(item.get("file_path") or "-")

            st.write("**Deskripsi:**")
            st.write(item.get("description") or "-")

            statuses = ["open", "reviewing", "resolved"]
            severities = ["critical", "high", "medium", "low", "info"]

            current_status = item.get("status", "open")
            current_severity = item.get("severity", "info")

            if current_status not in statuses:
                current_status = "open"

            if current_severity not in severities:
                current_severity = "info"

            with st.form(f"update_finding_{finding_id}"):
                new_status = st.selectbox(
                    "Status temuan",
                    statuses,
                    index=statuses.index(current_status)
                )

                new_severity = st.selectbox(
                    "Tingkat risiko",
                    severities,
                    index=severities.index(current_severity)
                )

                analyst_notes = st.text_area(
                    "Catatan analis",
                    value=item.get("analyst_notes") or ""
                )

                save_finding = st.form_submit_button(
                    "Simpan Perubahan",
                    type="primary"
                )

            if save_finding:
                update_status, update_result = api_request(
                    "PATCH",
                    f"/scans/{scan_id}/findings/{finding_id}",
                    headers=headers,
                    json={
                        "status": new_status,
                        "severity": new_severity,
                        "analyst_notes": analyst_notes
                    }
                )

                if update_status == 200:
                    st.success("Temuan berhasil diperbarui.")
                    st.rerun()
                else:
                    st.error(
                        update_result.get("detail", update_result)
                    )

            st.divider()

    elif status == 200:
        st.info("Belum ada findings untuk scan ini.")
    else:
        st.error("Gagal mengambil data findings.")

    st.markdown(
        '<div class="section-label" style="margin-top:20px">Mulai pemeriksaan</div>',
        unsafe_allow_html=True
    )

    a, b, c = st.columns(3)

    with a:
        st.markdown("**File Scanner**")
        st.caption("Periksa file atau folder dan hasilkan artefak laporan.")

    with b:
        st.markdown("**YARA Scanner**")
        st.caption("Cocokkan file dengan aturan YARA yang dipilih.")

    with c:
        st.markdown("**Live Triage**")
        st.caption("Kumpulkan informasi sistem dengan izin yang sesuai.")


def render_dashboard():
    reports = get_cases()

    # Ambil statistik dari Backend API
    headers = api_headers()

    case_status, case_data = api_request(
        "GET", "/cases", headers=headers
    )

    scan_status, scans_data = api_request(
        "GET", "/scans/", headers=headers
    )

    total_cases = 0
    total_scans = 0
    total_findings = 0

    if case_status == 200:
        total_cases = case_data.get(
            "total", len(case_data.get("cases", []))
        )

    if scan_status == 200 and isinstance(scans_data, list):
        total_scans = len(scans_data)

        for scan in scans_data:
            status, findings = api_request(
                "GET",
                f"/scans/{scan['id']}/findings",
                headers=headers
            )

            if status == 200 and isinstance(findings, list):
                total_findings += len(findings)

    st.markdown(
        '<div class="hero">'
        '<div class="hero-kicker">Security Operations Workspace</div>'
        '<div class="hero-title">Sentinel<span>Triage</span></div>'
        '<div class="hero-desc">Digital Forensics &amp; Malware Triage Platform</div>'
        '<div class="small-note">Deteksi · Analisis · Investigasi · Perlindungan</div>'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="section-label">Ringkasan Aktivitas Investigasi</div>',
        unsafe_allow_html=True
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Kasus", total_cases)
    c2.metric("Total Scan", total_scans)
    c3.metric("Total Findings", total_findings)
    c4.metric("Laporan Lokal", len(reports))

    if case_status == 200 and scan_status == 200:
        st.success("Backend API terhubung dan data berhasil dimuat.")
    else:
        st.warning("Sebagian data API belum berhasil dimuat.")

    st.divider()

    left, right = st.columns([1.35, 1])

    with left:
        st.markdown(
            '<div class="section-label">Laporan Terbaru</div>',
            unsafe_allow_html=True
        )

        if reports:
            rows = []

            for case_name, folder, files in reports[:7]:
                rows.append({
                    "ID Kasus": case_name,
                    "Artefak": ", ".join(files)
                })

            st.dataframe(
                rows,
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("Belum ada laporan lokal.")

    with right:
        st.markdown(
            '<div class="section-label">Status Workspace</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            """
            <div style="background:#0d1a2b;
                        border:1px solid #203852;
                        border-radius:13px;padding:17px">
                <div style="color:#37d6a0;font-weight:700">
                    ● SentinelTriage Aktif
                </div>
                <div class="small-note" style="margin-top:10px">
                    Modul investigasi terhubung dengan Backend API.
                </div>
                <hr style="border-color:#203852">
                <div style="color:#dbe8f5">Modul tersedia</div>
                <div class="small-note">
                    Workspace Investigasi · File Scanner ·
                    YARA Scanner · Live Triage · Report Center
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.divider()

    st.markdown(
        '<div class="section-label">Alur Kerja Investigasi</div>',
        unsafe_allow_html=True
    )

    a, b, c = st.columns(3)

    with a:
        st.markdown("**01 · Case Management**")
        st.caption("Membuat dan mengelola kasus investigasi.")

    with b:
        st.markdown("**02 · Security Scanning**")
        st.caption("Melakukan pemeriksaan file menggunakan YARA.")

    with c:
        st.markdown("**03 · Findings Analysis**")
        st.caption("Melihat dan mengevaluasi hasil temuan.")

# Authentication gate: users must log in before using the forensic tools.
inject_theme()
if not show_auth():
    st.stop()

show_user_sidebar()

with st.sidebar:
    render_brand()
    st.markdown(
        '<div class="small-note" style="margin:0 0 8px">NAVIGASI UTAMA</div>',
        unsafe_allow_html=True
    )

    page = st.radio(
        "Navigasi",
        [
            "Dashboard",
            "Workspace Investigasi",
            "File Scanner",
            "YARA Scanner",
            "Live Triage",
            "Report Center",
        ],
        label_visibility="collapsed",
        key="main_navigation",
    )

    st.divider()
    st.markdown(
        '<div class="small-note">SENTINELTRIAGE · VERSI PENGEMBANGAN</div>',
        unsafe_allow_html=True
    )
    st.caption(
        "Gunakan hanya pada perangkat dan data yang kamu berwenang periksa."
    )

user = st.session_state.get("auth_user") or {}
display_name = user.get("name", "Analis")
st.markdown(
    f'<div style="text-align:right;color:#8fa8c2;font-size:12px;margin-bottom:10px">SIGNED IN AS · {display_name}</div>',
    unsafe_allow_html=True
)

if page == "Dashboard":
    render_dashboard()
elif page == "Workspace Investigasi":
    show_investigation_workspace()
elif page == "Report Center":
    show_report_center()
else:
    st.markdown(f'<div class="section-label">{page}</div>', unsafe_allow_html=True)
    st.warning(
        "Gunakan hanya pada perangkat dan data yang kamu berwenang periksa. "
        "Hasil pemeriksaan bukan keputusan final bahwa perangkat bersih atau terinfeksi. "
        "Live collection dapat mengubah kondisi sistem."
    )

    with st.form(f"form_{page.lower().replace(' ', '_')}"):
        case_id = st.text_input(
            "ID kasus", value="case-002",
            help="Gunakan ID baru untuk setiap pemeriksaan."
        )
        operator = st.text_input("Nama analis", placeholder="Nama analis")
        scan_text = st.text_input(
            "Lokasi file atau folder (opsional jika mengunggah file)",
            placeholder="test-data/sampel-aman",
            help="Path relatif dihitung dari folder proyek SentinelTriage."
        )
        uploaded = st.file_uploader(
            "Atau unggah satu file untuk diperiksa (maksimal 100 MB)",
            help="File akan disimpan di folder kasus. Jangan unggah data yang tidak berwenang kamu periksa."
        )
        yara_text = st.text_input(
            "Lokasi aturan YARA",
            value="test-data/aturan/aturan-uji.yar" if page == "YARA Scanner" else "",
            placeholder="test-data/aturan/aturan-uji.yar",
        )

        if page == "Live Triage":
            st.info(
                "Live Triage mengumpulkan artefak dari Mac ini. "
                "Data dapat tidak lengkap karena izin atau batasan sistem."
            )
            live = True
        else:
            live = st.checkbox("Tambahkan Live Triage pada pemeriksaan ini", value=False)

        submitted = st.form_submit_button("Jalankan Pemeriksaan", type="primary", use_container_width=True)

    if submitted:
        run_triage(
            case_id=case_id,
            operator=operator,
            scan_text=scan_text,
            yara_text=yara_text,
            live=live,
            uploaded=uploaded,
            require_yara=(page == "YARA Scanner"),
        )

st.divider()
st.caption(
    "SentinelTriage membantu pemeriksaan awal. Temuan otomatis perlu diverifikasi analis; "
    "tidak ada temuan bukan jaminan perangkat bebas ancaman."
)
