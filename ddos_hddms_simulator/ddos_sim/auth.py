"""Session-based demo login for the Streamlit dashboard."""
import hashlib
import hmac
import os

import streamlit as st
from .config import DEFAULT_ADMIN_USERNAME, DEMO_ADMIN_PASSWORD


def _setting(name, fallback):
    """Read deployment secrets first, then environment variables, then local defaults."""
    try:
        value = st.secrets.get(name)
    except Exception:
        value = None
    return value or os.getenv(name, fallback)


def _credential_hash(value: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", value.encode("utf-8"), b"hddms-demo-salt-v1", 200_000
    )


def require_login():
    username = _setting("HDDMS_ADMIN_USERNAME", DEFAULT_ADMIN_USERNAME)
    password = _setting("HDDMS_ADMIN_PASSWORD", DEMO_ADMIN_PASSWORD)

    if st.session_state.get("authenticated"):
        with st.sidebar:
            st.success(f"Signed in as {username}")
            if st.button("Log out", use_container_width=True):
                st.session_state.clear()
                st.rerun()
        return True

    st.title("🛡️ HDDMS Administrator Login")
    st.caption("Access to the educational DDoS detection and mitigation simulator")
    with st.form("login_form"):
        entered_user = st.text_input("Username")
        entered_password = st.text_input("Password", type="password")
        submitted = st.form_submit_button(
            "Sign in", type="primary", use_container_width=True
        )

    if submitted:
        valid_user = hmac.compare_digest(entered_user.encode(), username.encode())
        valid_password = hmac.compare_digest(
            _credential_hash(entered_password), _credential_hash(password)
        )
        if valid_user and valid_password:
            st.session_state["authenticated"] = True
            st.rerun()
        st.error("Invalid username or password.")

    st.caption(
        "Administrator credentials are configured by the application owner. "
        "For hosted deployments, set HDDMS_ADMIN_USERNAME and HDDMS_ADMIN_PASSWORD "
        "in the app's Streamlit secrets."
    )
    return False
