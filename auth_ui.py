import os
import requests
import streamlit as st
from pathlib import Path

ROOT = Path(__file__).resolve().parent
API_BASE_URL = os.getenv("SENTINELTRIAGE_API_URL", "http://127.0.0.1:8002").rstrip("/")


def api_request(method, endpoint, **kwargs):
    try:
        response = requests.request(
            method,
            f"{API_BASE_URL}{endpoint}",
            timeout=10,
            **kwargs
        )
        try:
            data = response.json()
        except ValueError:
            data = {}
        return response.status_code, data
    except requests.RequestException:
        return 0, {"detail": "Backend API tidak aktif atau tidak dapat dijangkau."}


def _login_brand():
    logo_path = ROOT / "assets" / "sentineltriage-logo.svg"
    if logo_path.is_file():
        import base64
        encoded = base64.b64encode(logo_path.read_bytes()).decode("ascii")
        st.markdown(
            f'<div style="text-align:center;margin:2rem auto 1rem">'
            f'<img src="data:image/svg+xml;base64,{encoded}" style="width:86px;height:86px">'
            '<div style="font-size:27px;font-weight:700;color:#f4f8fd;margin-top:8px">'
            'Sentinel<span style="color:#3c9ff2">Triage</span></div>'
            '<div style="font-size:12px;letter-spacing:2px;color:#91a8c0;margin-top:5px">'
            'DIGITAL FORENSICS &amp; MALWARE TRIAGE</div></div>',
            unsafe_allow_html=True
        )
    else:
        st.title("SentinelTriage")


def show_auth():
    if "auth_token" not in st.session_state:
        st.session_state.auth_token = None
    if "auth_user" not in st.session_state:
        st.session_state.auth_user = None

    if st.session_state.auth_token:
        status, profile = api_request(
            "GET", "/auth/me",
            headers={"Authorization": f"Bearer {st.session_state.auth_token}"}
        )
        if status == 200:
            st.session_state.auth_user = profile
            return True
        st.session_state.auth_token = None
        st.session_state.auth_user = None

    st.markdown("""
    <style>
    .stApp {background:radial-gradient(ellipse at 50% 0%,#102746 0%,#07111f 55%,#050c16 100%);}
    div[data-testid="stForm"] {background:rgba(11,24,40,.82);border:1px solid #203852;border-radius:15px;padding:18px;}
    .block-container {max-width:680px;padding-top:2rem;}
    </style>
    """, unsafe_allow_html=True)
    _login_brand()
    st.markdown("<h3 style='text-align:center;color:#e8f1fb'>Masuk ke workspace Anda</h3>", unsafe_allow_html=True)
    st.caption("Platform pemeriksaan awal Digital Forensics dan Malware Triage.")

    login_tab, register_tab = st.tabs(["Login", "Buat Akun"])

    with login_tab:
        with st.form("login_form"):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login", use_container_width=True, type="primary")
        if submitted:
            status, data = api_request("POST", "/auth/login", json={"email": email, "password": password})
            if status == 200 and data.get("access_token"):
                st.session_state.auth_token = data["access_token"]
                st.session_state.auth_user = data.get("user")
                st.success("Login berhasil.")
                st.rerun()
            st.error(data.get("detail", "Login gagal. Periksa email dan password."))

    with register_tab:
        with st.form("register_form"):
            name = st.text_input("Nama lengkap")
            reg_email = st.text_input("Email", key="register_email")
            reg_password = st.text_input("Password (minimal 8 karakter)", type="password", key="register_password")
            submitted = st.form_submit_button("Buat Akun", use_container_width=True, type="primary")
        if submitted:
            status, data = api_request(
                "POST", "/auth/register",
                json={"name": name, "email": reg_email, "password": reg_password}
            )
            if status in (200, 201):
                st.success("Registrasi berhasil. Silakan login.")
            else:
                st.error(data.get("detail", "Registrasi gagal."))

    return False


def show_user_sidebar():
    user = st.session_state.get("auth_user") or {}
    with st.sidebar:
        st.divider()
        st.caption("AKUN PENGGUNA")
        st.write(user.get("name", "Pengguna"))
        st.caption(user.get("email", ""))
        if st.button("Logout", use_container_width=True):
            st.session_state.auth_token = None
            st.session_state.auth_user = None
            st.rerun()
