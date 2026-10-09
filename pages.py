"""
pages.py - Streamlit screens for accounts, legal pages, contact and the admin panel.
The processing tools themselves live in app.py / engine.py.
"""
from __future__ import annotations

from datetime import datetime
from urllib.parse import quote

import pandas as pd
import streamlit as st

import auth
from auth import AuthError

DEFAULT_UPDATED = "9 October 2026"

# --------------------------------------------------------------------------- #
# Default legal / about text (admins can edit these in Admin -> Content).
# These are starting templates, not legal advice - have them reviewed for your jurisdiction.
# --------------------------------------------------------------------------- #
ABOUT = """
**{site}** is an all-in-one PDF workspace: merge, split, reorder, convert, extract, watermark, number,
compress, protect, OCR and inspect your documents from any browser.

### What we care about
- **Privacy first.** Your PDFs are processed in memory to do the job you asked for. We don't store, read or share your documents.
- **Accuracy.** Every tool is tested against real files, and we tell you plainly where a tool has limits.
- **Simplicity.** No ads, no watermarks on your results, no clutter.

### What's inside
Organize (merge, split, reorder, rotate, crop) · Convert (text, tables, images) · Create (images or text to PDF) ·
Enhance (watermark, page numbers, OCR) · Secure (AES encryption, metadata) · Optimize (compression, inspector).

Questions or ideas? Reach us through the **Contact** page{contact_hint}.
"""

TERMS = """
By creating an account or using **{site}** you agree to these terms. If you don't agree, please don't use the service.

### 1. Your account
- Give accurate information and keep your password confidential. You're responsible for activity under your account.
- You must be at least 13 years old (or the minimum age in your country) to create an account.
- One person per account. Don't share credentials.

### 2. Acceptable use
You agree not to: upload content you don't have the right to process; use the service for anything unlawful,
harmful or fraudulent; try to break, probe or overload the service; bypass security, rate limits or access
controls; or use automated means to scrape or abuse the service.

### 3. Your files
You keep all rights to your files. We process them only to perform the operation you request and we don't claim
any ownership. You're responsible for having the right to process them.

### 4. Password-protected files
If you encrypt a PDF with this service and forget the password, **it cannot be recovered**. Keep a copy of the
original and your password somewhere safe.

### 5. No warranty
The service is provided "as is" and "as available". Tools can produce unexpected results on unusual files
(for example scans, complex layouts or damaged PDFs). Always keep your original documents and check important outputs.

### 6. Limitation of liability
To the fullest extent permitted by law, {site} and its operators are not liable for indirect, incidental or
consequential damages, or loss of data or profits, arising from your use of the service.

### 7. Suspension and termination
We may suspend or close accounts that break these terms or put the service or other users at risk. You can delete
your account yourself at any time from the Account page.

### 8. Changes
We may update these terms. Continued use after an update means you accept the new version.

### 9. Governing law and contact
These terms are governed by the laws of your operator's jurisdiction. Questions: {contact}.
"""

PRIVACY = """
This policy explains what **{site}** collects, why, and the choices you have.

### What we collect
- **Account data:** your name, email address and a *salted hash* of your password (we never store the password itself), plus your role, sign-up date and last sign-in time.
- **Usage log:** which tool you used and when, and how many bytes a compression saved. We **do not** record file names or file contents.
- **Messages:** what you send through the Contact form (name, email, subject, message).
- **Technical data:** the app uses a session cookie that is needed for the site to work. Your hosting provider may keep standard server logs (such as IP addresses) for security and reliability.

### Your documents
Files you upload are processed **in memory** to produce your result. We don't save them to disk, look at them, sell them or use them to train models. They are discarded when the session ends.

### How we use data
To run your account, secure the service (for example sign-in lockouts), provide support, understand which tools are used, and fix problems. We don't sell personal data and don't show advertising.

### Sharing
Only with the infrastructure providers that host the service, or when required by law.

### Retention and your choices
- You can change your name and password and **delete your account** at any time on the Account page. Deleting removes your profile, usage log and contact messages linked to your account.
- Password reset codes expire after 15 minutes.
- For a copy of your data or any other request, contact {contact}.

### Security
Passwords are hashed with PBKDF2-SHA256, repeated wrong passwords temporarily lock sign-in, and administrators can't see your password.

### Children
The service isn't intended for children under 13.

### Changes
If we make important changes we'll update this page and its date.
"""

LEGAL = {
    "about": ("ℹ️", "About", ABOUT),
    "terms": ("📜", "Terms of service", TERMS),
    "privacy": ("🔏", "Privacy policy", PRIVACY),
}


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _header(icon: str, title: str, sub: str = ""):
    st.markdown(f'<div class="page-title"><div class="ico">{icon}</div><h2>{title}</h2></div>'
                f'<div class="page-sub">{sub}</div>', unsafe_allow_html=True)


def _set(page: str, after: str | None = None):
    st.session_state["page"] = page
    if after:
        st.session_state["after_login"] = after


def link_button(label: str, page: str, key: str, after: str | None = None, **kw):
    return st.button(label, key=key, on_click=_set, args=(page, after), **kw)


def _fmt(ts) -> str:
    return datetime.fromtimestamp(ts).strftime("%d %b %Y, %H:%M") if ts else "—"


def _center():
    return st.columns([1, 1.7, 1])[1]


def current_user() -> dict | None:
    uid = st.session_state.get("uid")
    if not uid:
        return None
    u = auth.get_user(uid)
    if not u or u["status"] != "active":
        st.session_state.pop("uid", None)
        return None
    return u


def logout():
    st.session_state.pop("uid", None)
    st.session_state.pop("tmp_pw", None)
    st.session_state["page"] = "home"


def _sign_in(user_id: int):
    st.session_state["uid"] = user_id
    st.session_state["page"] = st.session_state.pop("after_login", "home")
    st.rerun()


def home_cta(user):
    if user:
        return
    c = st.columns([1.2, 1, 2])
    with c[0]:
        link_button("✨ Create free account", "signup", "cta_signup", type="primary", use_container_width=True)
    with c[1]:
        link_button("Sign in", "login", "cta_login", use_container_width=True)


# --------------------------------------------------------------------------- #
# Auth screens
# --------------------------------------------------------------------------- #
def setup_admin_page():
    _header("🛡️", "Set up your administrator", "First run: create the account that will manage this site.")
    with _center():
        st.info("This screen only appears while no administrator exists. On a public deployment, set the "
                "`ADMIN_EMAIL` and `ADMIN_PASSWORD` secrets instead so nobody else can claim this role first.")
        with st.form("setup_admin"):
            name = st.text_input("Your name")
            email = st.text_input("Admin email")
            pw = st.text_input("Password", type="password", help="8+ characters with a letter and a number")
            pw2 = st.text_input("Confirm password", type="password")
            go = st.form_submit_button("Create administrator", type="primary", use_container_width=True)
        if go:
            if pw != pw2:
                st.error("Passwords don't match.")
            else:
                try:
                    uid = auth.create_user(email, name, pw, role="admin")
                except AuthError as ex:
                    st.error(str(ex))
                else:
                    st.session_state["uid"] = uid
                    st.session_state["page"] = "admin"
                    st.rerun()


def login_page():
    _header("🔑", "Sign in", "Welcome back — pick up where you left off.")
    with _center():
        with st.form("login_form"):
            email = st.text_input("Email", key="li_email")
            pw = st.text_input("Password", type="password", key="li_pw")
            go = st.form_submit_button("Sign in", type="primary", use_container_width=True)
        if go:
            try:
                u = auth.authenticate(email, pw)
            except AuthError as ex:
                st.error(str(ex))
            else:
                _sign_in(u["id"])
        c1, c2 = st.columns(2)
        with c1:
            link_button("Forgot password?", "forgot", "lk_forgot", use_container_width=True)
        with c2:
            if auth.get_setting("signups_enabled") == "1":
                link_button("Create account", "signup", "lk_signup", use_container_width=True)


def signup_page():
    _header("✨", "Create your account", "Free, private and takes under a minute.")
    with _center():
        if auth.get_setting("signups_enabled") != "1":
            st.warning("New registrations are currently closed.")
            link_button("Back to sign in", "login", "su_back")
            return
        with st.form("signup_form"):
            name = st.text_input("Full name")
            email = st.text_input("Email")
            pw = st.text_input("Password", type="password", help="At least 8 characters, with a letter and a number")
            pw2 = st.text_input("Confirm password", type="password")
            agree = st.checkbox("I agree to the Terms of service and the Privacy policy")
            go = st.form_submit_button("Create account", type="primary", use_container_width=True)
        if go:
            if pw != pw2:
                st.error("Passwords don't match.")
            elif not agree:
                st.error("Please accept the Terms and Privacy policy to continue.")
            else:
                try:
                    uid = auth.create_user(email, name, pw)
                except AuthError as ex:
                    st.error(str(ex))
                else:
                    _sign_in(uid)
        c1, c2, c3 = st.columns(3)
        with c1:
            link_button("Terms", "terms", "su_terms", use_container_width=True)
        with c2:
            link_button("Privacy", "privacy", "su_priv", use_container_width=True)
        with c3:
            link_button("Sign in", "login", "su_login", use_container_width=True)


def forgot_page():
    _header("🔓", "Reset your password", "We'll help you get back in.")
    with _center():
        by_email = auth.smtp_configured()
        tabs = st.tabs(["Request a reset", "I have a code"]) if by_email else [st.container()]
        with tabs[0]:
            with st.form("forgot_form"):
                email = st.text_input("Account email")
                go = st.form_submit_button("Send reset request", type="primary", use_container_width=True)
            if go:
                if not auth.EMAIL_RE.match(auth.norm_email(email)):
                    st.error("Enter a valid email address.")
                else:
                    auth.request_reset(email)
                    if by_email:
                        st.success("If an account exists for that email, we've sent a 6-digit code. "
                                   "It expires in 15 minutes. Open the **I have a code** tab to finish.")
                    else:
                        st.success("If an account exists for that email, the administrator has been notified and "
                                   "will contact you with a temporary password. You'll be asked to choose a new "
                                   "password when you sign in.")
        if by_email:
            with tabs[1]:
                with st.form("code_form"):
                    e2 = st.text_input("Account email", key="fc_email")
                    code = st.text_input("6-digit code", max_chars=6)
                    p1 = st.text_input("New password", type="password")
                    p2 = st.text_input("Confirm new password", type="password")
                    go2 = st.form_submit_button("Set new password", type="primary", use_container_width=True)
                if go2:
                    if p1 != p2:
                        st.error("Passwords don't match.")
                    else:
                        try:
                            auth.complete_reset(e2, code, p1)
                        except AuthError as ex:
                            st.error(str(ex))
                        else:
                            st.success("Password updated. You can sign in now.")
        link_button("Back to sign in", "login", "fg_back", use_container_width=True)


def force_change_page(user: dict):
    _header("🔐", "Choose a new password", "Your password was reset by an administrator. Set your own to continue.")
    with _center():
        with st.form("force_form"):
            p1 = st.text_input("New password", type="password")
            p2 = st.text_input("Confirm new password", type="password")
            go = st.form_submit_button("Save and continue", type="primary", use_container_width=True)
        if go:
            if p1 != p2:
                st.error("Passwords don't match.")
            else:
                try:
                    auth.finish_forced_change(user["id"], p1)
                except AuthError as ex:
                    st.error(str(ex))
                else:
                    st.session_state["page"] = "home"
                    st.rerun()
        st.button("Sign out", key="force_out", on_click=logout)


def login_required(page: str):
    _header("🔒", "Sign in to use this tool", "A free account is needed to run the PDF tools.")
    with _center():
        st.info("Create a free account or sign in. Your files are processed in memory and never stored.")
        c1, c2 = st.columns(2)
        with c1:
            link_button("Sign in", "login", "lr_login", after=page, type="primary", use_container_width=True)
        with c2:
            link_button("Create account", "signup", "lr_signup", after=page, use_container_width=True)


def maintenance_page():
    _header("🛠️", "We'll be right back", "The site is undergoing maintenance.")
    st.info(auth.get_setting("announcement") or "Please check back shortly.")


# --------------------------------------------------------------------------- #
# Account
# --------------------------------------------------------------------------- #
def account_page(user: dict):
    _header("👤", "Your account", "Manage your profile, password and data.")
    t1, t2, t3 = st.tabs(["Profile", "Password", "Data and privacy"])
    with t1:
        c = st.columns(3)
        c[0].metric("Member since", datetime.fromtimestamp(user["created_at"]).strftime("%d %b %Y"))
        c[1].metric("Role", user["role"].title())
        c[2].metric("Operations", auth.user_usage_count(user["id"]))
        with st.form("profile_form"):
            st.text_input("Email", user["email"], disabled=True)
            name = st.text_input("Name", user["name"])
            if st.form_submit_button("Save profile", type="primary"):
                try:
                    auth.update_name(user["id"], name)
                except AuthError as ex:
                    st.error(str(ex))
                else:
                    st.success("Profile updated.")
                    st.rerun()
    with t2:
        with st.form("pw_form"):
            old = st.text_input("Current password", type="password")
            p1 = st.text_input("New password", type="password")
            p2 = st.text_input("Confirm new password", type="password")
            if st.form_submit_button("Change password", type="primary"):
                if p1 != p2:
                    st.error("Passwords don't match.")
                else:
                    try:
                        auth.change_password(user["id"], old, p1)
                    except AuthError as ex:
                        st.error(str(ex))
                    else:
                        st.success("Password changed.")
    with t3:
        st.write("Your PDFs are never stored. We keep your profile and a simple usage log (tool name and time). "
                 "Read the full details in the Privacy policy.")
        link_button("Read the Privacy policy", "privacy", "ac_priv")
        st.divider()
        st.subheader("Delete account")
        st.caption("This permanently removes your profile, usage log and contact messages. It can't be undone.")
        with st.form("del_form"):
            pw = st.text_input("Confirm with your password", type="password")
            sure = st.checkbox("I understand this is permanent")
            if st.form_submit_button("Delete my account"):
                if not sure:
                    st.error("Tick the box to confirm.")
                else:
                    try:
                        auth.delete_account(user["id"], pw)
                    except AuthError as ex:
                        st.error(str(ex))
                    else:
                        logout()
                        st.rerun()


# --------------------------------------------------------------------------- #
# About / Terms / Privacy / Contact
# --------------------------------------------------------------------------- #
def _render_legal(key: str) -> str:
    default = LEGAL[key][2]
    body = auth.get_setting(f"page_{key}", "") or default
    site = auth.get_setting("site_name")
    contact = auth.get_setting("contact_email")
    return (body.replace("{site}", site)
            .replace("{contact}", contact or "the Contact page")
            .replace("{contact_hint}", f" or email **{contact}**" if contact else ""))


def info_page(key: str):
    icon, title, _ = LEGAL[key]
    updated = auth.get_setting(f"page_{key}_updated", "") or DEFAULT_UPDATED
    _header(icon, title, f"Last updated {updated}")
    st.markdown(_render_legal(key))
    st.divider()
    c = st.columns(4)
    for col, (pid, label) in zip(c, [("about", "About"), ("terms", "Terms"), ("privacy", "Privacy"),
                                     ("contact", "Contact us")]):
        with col:
            if pid != key:
                link_button(label, pid, f"ip_{key}_{pid}", use_container_width=True)


def contact_page():
    _header("✉️", "Contact us", "Questions, feedback or a problem? We read every message.")
    user = current_user()
    contact = auth.get_setting("contact_email")
    c1, c2 = st.columns([1.5, 1])
    with c1:
        with st.form("contact_form", clear_on_submit=True):
            name = st.text_input("Your name", user["name"] if user else "")
            email = st.text_input("Your email", user["email"] if user else "")
            subject = st.selectbox("Topic", ["General question", "Report a problem", "Feature request",
                                             "Account or password help", "Privacy request", "Other"])
            body = st.text_area("Message", height=160)
            go = st.form_submit_button("Send message", type="primary", use_container_width=True)
        if go:
            sent = [t for t in st.session_state.get("contact_times", []) if t > auth.now() - 3600]
            if len(sent) >= 3:
                st.error("You've sent several messages recently. Please try again later.")
            else:
                try:
                    auth.add_message(name, email, subject, body, user["id"] if user else None)
                except AuthError as ex:
                    st.error(str(ex))
                else:
                    st.session_state["contact_times"] = sent + [auth.now()]
                    st.success("Thanks — your message has been sent. We'll reply by email.")
    with c2:
        st.markdown("#### Other ways to reach us")
        st.write(f"📧 {contact}" if contact else "📧 Use the form and we'll reply to your email.")
        st.write("⏱️ We usually reply within 2 working days.")
        st.markdown("#### Helpful pages")
        link_button("Privacy policy", "privacy", "ct_priv", use_container_width=True)
        link_button("Terms of service", "terms", "ct_terms", use_container_width=True)


# --------------------------------------------------------------------------- #
# Admin panel
# --------------------------------------------------------------------------- #
def _do(fn, *args, ok: str = "Done."):
    try:
        fn(*args)
    except AuthError as ex:
        st.session_state["flash"] = ("error", str(ex))
    else:
        st.session_state["flash"] = ("success", ok)
    st.rerun()


def _show_tmp():
    tmp = st.session_state.get("tmp_pw")
    if tmp:
        st.warning(f"One-time password for **{tmp[0]}** — shown once. Share it privately; "
                   "they'll be asked to choose a new password at sign-in.")
        st.code(tmp[1], language=None)
        if st.button("Hide password", key="hide_tmp"):
            st.session_state.pop("tmp_pw", None)
            st.rerun()


def admin_page(user: dict):
    if user["role"] != "admin":
        st.error("Administrators only.")
        return
    _header("🛡️", "Admin panel", "Manage users, messages, content and site settings.")
    flash = st.session_state.pop("flash", None)
    if flash:
        (st.success if flash[0] == "success" else st.error)(flash[1])
    s = auth.stats()
    tabs = st.tabs(["Overview", "Users", f"Resets ({s['resets']})", f"Messages ({s['new_msgs']})",
                    "Activity", "Settings", "Content"])

    # --- Overview
    with tabs[0]:
        c = st.columns(4)
        c[0].metric("Users", s["users"], f"+{s['new7']} this week")
        c[1].metric("Active (24h)", s["active24"])
        c[2].metric("Operations", s["ops"], f"{s['ops24']} today")
        c[3].metric("Open messages", s["new_msgs"])
        c = st.columns(4)
        c[0].metric("Admins", s["admins"])
        c[1].metric("Suspended", s["suspended"])
        c[2].metric("Reset requests", s["resets"])
        c[3].metric("Bytes saved", f"{s['saved'] / 1048576:.1f} MB")
        per_day = auth.usage_per_day(14)
        if per_day:
            st.subheader("Operations, last 14 days")
            st.bar_chart(pd.DataFrame(per_day, columns=["Day", "Operations"]).set_index("Day"))
        else:
            st.caption("No tool usage recorded yet.")
        st.caption("Email delivery for password resets: "
                   + ("✅ SMTP configured" if auth.smtp_configured() else "⚠️ not configured — resets go to the admin queue"))

    # --- Users
    with tabs[1]:
        _show_tmp()
        q = st.text_input("Search by name or email", key="adm_q")
        users = auth.list_users(q)
        if not users:
            st.info("No users found.")
        else:
            df = pd.DataFrame(users)
            for col in ("created_at", "last_login"):
                df[col] = df[col].map(_fmt)
            st.dataframe(df.rename(columns={"created_at": "joined", "last_login": "last sign-in"}),
                         hide_index=True, use_container_width=True)
            st.download_button("⬇️ Export users (CSV)", df.to_csv(index=False).encode(), "users.csv", "text/csv")
            by_id = {u["id"]: u for u in users}
            sel = st.selectbox("Manage a user", list(by_id), format_func=lambda i: f"{by_id[i]['name']} · {by_id[i]['email']}")
            t = by_id[sel]
            st.caption(f"Role: **{t['role']}** · Status: **{t['status']}** · Operations: **{t['ops']}**")
            a, b, c, d = st.columns(4)
            if t["status"] == "active":
                if a.button("⏸ Suspend", key="u_susp", use_container_width=True):
                    _do(auth.set_status, user["id"], sel, "suspended", ok="User suspended.")
            elif a.button("▶ Reactivate", key="u_act", use_container_width=True):
                _do(auth.set_status, user["id"], sel, "active", ok="User reactivated.")
            if t["role"] == "user":
                if b.button("⬆ Make admin", key="u_adm", use_container_width=True):
                    _do(auth.set_role, user["id"], sel, "admin", ok="Role updated.")
            elif b.button("⬇ Make user", key="u_usr", use_container_width=True):
                _do(auth.set_role, user["id"], sel, "user", ok="Role updated.")
            if c.button("🔑 Temp password", key="u_tmp", use_container_width=True):
                st.session_state["tmp_pw"] = (t["email"], auth.issue_temp_password(sel))
                st.rerun()
            with d:
                confirm = st.checkbox("Confirm delete", key="u_conf")
                if st.button("🗑 Delete", key="u_del", use_container_width=True, disabled=not confirm):
                    _do(auth.admin_delete_user, user["id"], sel, ok="User deleted.")

    # --- Reset queue
    with tabs[2]:
        _show_tmp()
        pend = auth.pending_admin_resets()
        if not pend:
            st.info("No pending password reset requests.")
        for r in pend:
            c1, c2, c3 = st.columns([3, 1.4, 1])
            c1.write(f"**{r['name']}** · {r['email']}  \n{_fmt(r['created_at'])}")
            if c2.button("Issue temp password", key=f"rs_{r['reset_id']}"):
                st.session_state["tmp_pw"] = (r["email"], auth.issue_temp_password(r["user_id"]))
                st.rerun()
            if c3.button("Dismiss", key=f"rd_{r['reset_id']}"):
                auth.dismiss_reset(r["reset_id"])
                st.rerun()

    # --- Messages
    with tabs[3]:
        flt = st.radio("Show", ["new", "resolved", "all"], horizontal=True, key="msg_flt")
        msgs = auth.list_messages(None if flt == "all" else flt)
        if not msgs:
            st.info("Nothing here.")
        for m in msgs:
            with st.expander(f"{'🆕 ' if m['status'] == 'new' else ''}{m['subject'] or '(no subject)'} — {m['name']} · {_fmt(m['created_at'])}"):
                st.write(m["body"])
                st.markdown(f"[✉️ Reply to {m['email']}](mailto:{m['email']}?subject={quote('Re: ' + (m['subject'] or 'your message'))})")
                c1, c2 = st.columns(2)
                if m["status"] == "new":
                    if c1.button("Mark resolved", key=f"mr_{m['id']}"):
                        auth.set_message_status(m["id"], "resolved")
                        st.rerun()
                elif c1.button("Reopen", key=f"mo_{m['id']}"):
                    auth.set_message_status(m["id"], "new")
                    st.rerun()
                if c2.button("Delete", key=f"md_{m['id']}"):
                    auth.delete_message(m["id"])
                    st.rerun()

    # --- Activity
    with tabs[4]:
        by_tool = auth.usage_by_tool(30)
        if by_tool:
            st.subheader("Most used tools (30 days)")
            st.bar_chart(pd.DataFrame(by_tool, columns=["Tool", "Uses"]).set_index("Tool"))
            rec = pd.DataFrame(auth.recent_usage(100))
            rec["ts"] = rec["ts"].map(_fmt)
            st.subheader("Recent activity")
            st.dataframe(rec.rename(columns={"ts": "time", "who": "user"}), hide_index=True, use_container_width=True)
        else:
            st.info("No activity yet.")

    # --- Settings
    with tabs[5]:
        with st.form("settings_form"):
            site = st.text_input("Site name", auth.get_setting("site_name"))
            contact = st.text_input("Public contact email", auth.get_setting("contact_email"))
            ann = st.text_input("Announcement banner (leave blank for none)", auth.get_setting("announcement"))
            c = st.columns(3)
            su = c[0].toggle("Allow new sign-ups", auth.get_setting("signups_enabled") == "1")
            rl = c[1].toggle("Require login to use tools", auth.get_setting("require_login") == "1")
            mt = c[2].toggle("Maintenance mode", auth.get_setting("maintenance") == "1",
                             help="Only administrators can use the site while this is on.")
            if st.form_submit_button("Save settings", type="primary"):
                for k, v in {"site_name": site or "PDF ToolHub", "contact_email": contact, "announcement": ann,
                             "signups_enabled": "1" if su else "0", "require_login": "1" if rl else "0",
                             "maintenance": "1" if mt else "0"}.items():
                    auth.set_setting(k, v)
                _do(lambda: None, ok="Settings saved.")
        st.caption("Email for password resets uses these environment variables / secrets: SMTP_HOST, SMTP_PORT, "
                   "SMTP_USER, SMTP_PASS, SMTP_FROM.")

    # --- Content editor
    with tabs[6]:
        page = st.selectbox("Page", list(LEGAL), format_func=lambda k: LEGAL[k][1])
        st.caption("Markdown supported. Placeholders: {site}, {contact}. These are starting templates, not legal "
                   "advice — have them reviewed for your jurisdiction before launching publicly.")
        text = st.text_area("Content", auth.get_setting(f"page_{page}", "") or LEGAL[page][2], height=380,
                            key=f"ed_{page}")
        c1, c2 = st.columns(2)
        if c1.button("Save page", type="primary", key=f"sv_{page}"):
            auth.set_setting(f"page_{page}", text)
            today = datetime.now()
            auth.set_setting(f"page_{page}_updated", f"{today.day} {today:%B %Y}")
            _do(lambda: None, ok="Page saved.")
        if c2.button("Restore default", key=f"rs_{page}"):
            auth.set_setting(f"page_{page}", "")
            auth.set_setting(f"page_{page}_updated", "")
            st.session_state.pop(f"ed_{page}", None)
            _do(lambda: None, ok="Default restored.")
