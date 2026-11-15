import streamlit as st

import config
from core import qr_analyzer, threat_intelligence, workflow
from core.demo_data import by_type, make_demo_qr_png
from database import db
from utils.helpers import defang_display
from utils.ui import render_result


def _options(prefix):
    c1, c2 = st.columns(2)
    dns = c1.checkbox("DNS lookup of the hostname (no connection to the site)", key=f"{prefix}_dns")
    keys = any(threat_intelligence.available_sources().values())
    intel = c2.checkbox("Query threat intelligence (VirusTotal / URLhaus)", key=f"{prefix}_intel", disabled=not keys,
                        help="Enable by setting API keys in .env or Streamlit secrets." if not keys else None)
    return dns, intel


def _run(kind, content, evidence_text, dns=False, intel=False):
    """Normal user scan: ALWAYS stored as a real investigation (is_demo=False). Errors are shown, never swallowed."""
    try:
        with st.spinner("Analysing evidence (nothing is opened or visited)..."):
            inv_id, saved = workflow.run_and_store(kind, content, evidence_text, is_demo=False, dns=dns, intel=intel)
    except ValueError as exc:
        st.error(f"Input rejected: {exc}")
        return
    except workflow.AnalysisError as exc:
        st.error(f"{exc}. Nothing was stored. Details were written to the application log.")
        return
    except workflow.StorageError as exc:
        st.error(str(exc))
        return
    st.session_state["current_id"] = inv_id
    st.session_state["last_result"] = saved


def _save_demo(case):
    """Explicit demo action: the ONLY scanner path that creates is_demo=True records (idempotent)."""
    try:
        added, existing = workflow.load_demo_records([case])
    except (ValueError, workflow.AnalysisError, workflow.StorageError) as exc:
        st.session_state["demo_error"] = f"Demo record could not be saved: {exc}"   # shown by render() after the callback
        return
    inv_id = (added or existing)[0]
    st.session_state["current_id"] = inv_id
    st.session_state["last_result"] = db.get_investigation(inv_id)
    st.session_state["demo_notice"] = ("Demo record created." if added else "This demo record was already saved - opened the existing one.")


def _load_demo(key, content):
    st.session_state[key] = content


def _demo_picker(kind, key):
    demos = by_type(kind)
    labels = {d["label"]: d for d in demos}
    with st.expander("Demonstration cases (fictional data - not clickable)"):
        choice = st.selectbox("Case", list(labels), key=f"demo_sel_{key}")
        d = labels[choice]
        st.code(d["content"] if kind != "email" else d["content"][:900], language=None)
        if d.get("note"):
            st.caption(d["note"])
        c1, c2 = st.columns(2)
        c1.button("Load into scanner", key=f"demo_btn_{key}", on_click=_load_demo, args=(key, d["content"]),
                  help="Only fills the input box. Pressing Scan afterwards stores a normal (real) investigation.")
        c2.button("Save as DEMO record", key=f"demo_save_{key}", on_click=_save_demo, args=(d,),
                  help="Analyses this example and stores it labelled as demonstration data (never duplicated).")


def render():
    st.title("Threat Scanner")
    st.caption("Submit evidence. PhishTrace analyses it statically - it never opens links, follows redirects or runs files.")
    st.info("Scans you run here are stored as REAL investigations. Demonstration cases are only stored as demo data when you press "
            "'Save as DEMO record'; loading an example into the box does not change that.")
    if st.session_state.get("demo_error"):
        st.error(st.session_state.pop("demo_error"))
    if st.session_state.get("demo_notice"):
        st.success(st.session_state.pop("demo_notice"))
    t_url, t_mail, t_msg, t_qr = st.tabs(["URL", "Email", "Message / SMS", "QR code"])

    with t_url:
        _demo_picker("url", "url_input")
        url = st.text_input("URL to analyse", key="url_input", placeholder="https://example.com/login", max_chars=config.MAX_URL_CHARS)
        dns, intel = _options("url")
        if st.button("Scan URL", type="primary", key="scan_url"):
            if not url.strip():
                st.warning("Enter a URL first.")
            else:
                _run("url", url, url, dns, intel)

    with t_mail:
        _demo_picker("email", "email_input")
        up = st.file_uploader(".eml file (max 5 MB, never executed)", type=["eml", "txt"], key="eml_up")
        text = st.text_area("...or paste the raw email (headers + body)", key="email_input", height=220, max_chars=config.MAX_TEXT_CHARS)
        dns, intel = _options("mail")
        if st.button("Scan email", type="primary", key="scan_mail"):
            if up is not None:
                data = up.getvalue()
                if len(data) > config.MAX_UPLOAD_BYTES:
                    st.error("File too large (5 MB limit).")
                else:
                    _run("email", data, data.decode("utf-8", "replace"), dns, intel)
            elif text.strip():
                _run("email", text, text, dns, intel)
            else:
                st.warning("Paste an email or upload an .eml file.")

    with t_msg:
        _demo_picker("message", "msg_input")
        msg = st.text_area("Paste the SMS / WhatsApp / chat message", key="msg_input", height=160, max_chars=config.MAX_TEXT_CHARS)
        st.caption("Please do not paste real OTPs, PINs or card numbers; sensitive-looking values are masked before storage.")
        dns, intel = _options("msg")
        if st.button("Scan message", type="primary", key="scan_msg"):
            if msg.strip():
                _run("message", msg, msg, dns, intel)
            else:
                st.warning("Paste a message first.")

    with t_qr:
        dec = qr_analyzer.decoders_available()
        st.caption(f"Decoders - pyzbar: {'yes' if dec['pyzbar'] else 'no'}, OpenCV: {'yes' if dec['opencv'] else 'no'}. "
                   "The QR is decoded to text only; the destination is never visited.")
        up = st.file_uploader("QR image (png/jpg/webp/bmp, max 5 MB)", type=["png", "jpg", "jpeg", "webp", "bmp"], key="qr_up")
        dns, intel = _options("qr")
        if st.button("Scan QR image", type="primary", key="scan_qr"):
            if up is None:
                st.warning("Upload a QR image first.")
            else:
                data = up.getvalue()
                if len(data) > config.MAX_UPLOAD_BYTES:
                    st.error("File too large (5 MB limit).")
                else:
                    payloads, err = qr_analyzer.decode_qr(data)
                    if err:
                        st.error(err)
                    else:
                        _run("qr", data, "QR image upload\nDecoded payload: " + payloads[0], dns, intel)
        with st.expander("Demonstration QR (fictional UPI refund trap)"):
            demo = by_type("qr_payload")[0]
            st.code(demo["content"], language=None)
            png = make_demo_qr_png(demo["content"])
            if png:
                st.image(png, width=200, caption="Demo QR generated locally")
                st.download_button("Download demo QR", png, "demo_qr.png", "image/png", key="dl_demo_qr")
            st.button("Save demo QR payload as DEMO record", key="scan_qr_demo", on_click=_save_demo, args=(demo,))

    res = st.session_state.get("last_result")
    if res:
        st.divider()
        st.subheader("Latest result")
        render_result(res, key="scanner")
