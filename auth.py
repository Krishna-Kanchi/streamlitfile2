"""
auth.py - accounts, password reset, contact inbox, usage log and admin data layer.

SQLite + Python standard library only (no extra dependencies), no Streamlit imports,
so everything here can be unit-tested and reused.

Security notes
- Passwords: PBKDF2-HMAC-SHA256, 260k iterations, per-user random salt, constant-time compare.
- Login lockout: 5 wrong passwords -> 15 minute lock. Generic error messages (no account probing).
- Password reset: 6-digit code, hashed, 15 min expiry, max 5 tries, max 3 requests/hour. Delivered by
  e-mail if SMTP_* env vars are set; otherwise the request goes to the admin queue and the admin issues a
  one-time temporary password (the user must change it at next sign-in).
"""
from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import time
from contextlib import contextmanager
from email.message import EmailMessage
from pathlib import Path

DB_PATH = Path(os.environ.get("TOOLHUB_DB") or Path(__file__).parent / "data" / "toolhub.db")
ITERATIONS = 260_000
MAX_FAILS, LOCK_MINUTES, CODE_MINUTES, MAX_CODE_TRIES = 5, 15, 15, 5
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
GENERIC_LOGIN_ERROR = "Incorrect email or password."
COMMON_PASSWORDS = {"password1", "password123", "12345678", "123456789", "qwerty123", "iloveyou1",
                    "admin123", "welcome1", "abc12345", "11111111a"}
DEFAULT_SETTINGS = {
    "site_name": "PDF ToolHub", "signups_enabled": "1", "require_login": "1",
    "maintenance": "0", "announcement": "", "contact_email": "",
}


class AuthError(Exception):
    """User-facing error."""


def now() -> int:
    return int(time.time())


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #
@contextmanager
def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init() -> None:
    with db() as con:
        con.executescript("""
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  pw_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active',
  created_at INTEGER NOT NULL, last_login INTEGER DEFAULT 0, fails INTEGER DEFAULT 0,
  locked_until INTEGER DEFAULT 0, must_change INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS resets(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, via TEXT NOT NULL,
  code_hash TEXT, expires INTEGER DEFAULT 0, used INTEGER DEFAULT 0, attempts INTEGER DEFAULT 0,
  handled INTEGER DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, email TEXT, subject TEXT,
  body TEXT, status TEXT DEFAULT 'new', created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS usage(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, tool TEXT NOT NULL,
  saved INTEGER DEFAULT 0, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS ix_usage_ts ON usage(ts);
CREATE INDEX IF NOT EXISTS ix_usage_user ON usage(user_id);
""")


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, it, salt, h = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(dk.hex(), h)
    except Exception:
        return False


_DUMMY_HASH: str | None = None


def check_password_strength(pw: str) -> None:
    if not isinstance(pw, str) or len(pw) < 8:
        raise AuthError("Use at least 8 characters for your password.")
    if len(pw) > 128:
        raise AuthError("Password is too long (max 128 characters).")
    if not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        raise AuthError("Your password needs at least one letter and one number.")
    if pw.lower() in COMMON_PASSWORDS:
        raise AuthError("That password is too common. Choose something harder to guess.")


def norm_email(email: str) -> str:
    return (email or "").strip().lower()


def _user(row) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    d.pop("pw_hash", None)
    return d


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
def get_setting(key: str, default: str | None = None) -> str:
    with db() as con:
        r = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if r is not None:
        return r["value"]
    return DEFAULT_SETTINGS.get(key, "") if default is None else default


def set_setting(key: str, value: str) -> None:
    with db() as con:
        con.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


# --------------------------------------------------------------------------- #
# Accounts
# --------------------------------------------------------------------------- #
def create_user(email: str, name: str, password: str, role: str = "user") -> int:
    email, name = norm_email(email), (name or "").strip()
    if not EMAIL_RE.match(email) or len(email) > 254:
        raise AuthError("Enter a valid email address.")
    if not 2 <= len(name) <= 60:
        raise AuthError("Enter your name (2 to 60 characters).")
    check_password_strength(password)
    try:
        with db() as con:
            cur = con.execute("INSERT INTO users(email,name,pw_hash,role,created_at) VALUES(?,?,?,?,?)",
                              (email, name, hash_password(password), role, now()))
            return int(cur.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise AuthError("An account with this email already exists. Try signing in.") from exc


def authenticate(email: str, password: str) -> dict:
    global _DUMMY_HASH
    email = norm_email(email)
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if row is None:
            _DUMMY_HASH = _DUMMY_HASH or hash_password("dummy-Password-1")
            verify_password(password or "", _DUMMY_HASH)  # equalise timing
            raise AuthError(GENERIC_LOGIN_ERROR)
        if row["locked_until"] > now():
            mins = math.ceil((row["locked_until"] - now()) / 60)
            raise AuthError(f"Too many failed attempts. Try again in {mins} minute(s).")
        if not verify_password(password or "", row["pw_hash"]):
            fails = row["fails"] + 1
            if fails >= MAX_FAILS:
                con.execute("UPDATE users SET fails=0, locked_until=? WHERE id=?",
                            (now() + LOCK_MINUTES * 60, row["id"]))
            else:
                con.execute("UPDATE users SET fails=? WHERE id=?", (fails, row["id"]))
            con.commit()  # persist before raising
            raise AuthError(GENERIC_LOGIN_ERROR)
        if row["status"] != "active":
            raise AuthError("This account is suspended. Please contact support.")
        con.execute("UPDATE users SET fails=0, locked_until=0, last_login=? WHERE id=?", (now(), row["id"]))
        return _user(row)


def get_user(user_id: int) -> dict | None:
    with db() as con:
        return _user(con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())


def user_by_email(email: str) -> dict | None:
    with db() as con:
        return _user(con.execute("SELECT * FROM users WHERE email=?", (norm_email(email),)).fetchone())


def has_admin() -> bool:
    with db() as con:
        return con.execute("SELECT 1 FROM users WHERE role='admin' AND status='active' LIMIT 1").fetchone() is not None


def _active_admins(con) -> int:
    return con.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND status='active'").fetchone()[0]


def bootstrap_admin_from_env() -> str | None:
    """Create/promote the admin from ADMIN_EMAIL + ADMIN_PASSWORD env vars. Returns an error string or None."""
    email, pw = os.environ.get("ADMIN_EMAIL"), os.environ.get("ADMIN_PASSWORD")
    if not email or not pw or has_admin():
        return None
    try:
        existing = user_by_email(email)
        if existing:
            with db() as con:
                con.execute("UPDATE users SET role='admin', status='active' WHERE id=?", (existing["id"],))
        else:
            create_user(email, os.environ.get("ADMIN_NAME", "Administrator"), pw, role="admin")
    except AuthError as ex:
        return f"ADMIN_EMAIL / ADMIN_PASSWORD could not be used: {ex}"
    return None


def update_name(user_id: int, name: str) -> None:
    name = (name or "").strip()
    if not 2 <= len(name) <= 60:
        raise AuthError("Enter your name (2 to 60 characters).")
    with db() as con:
        con.execute("UPDATE users SET name=? WHERE id=?", (name, user_id))


def change_password(user_id: int, old: str, new: str) -> None:
    check_password_strength(new)
    with db() as con:
        row = con.execute("SELECT pw_hash FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or not verify_password(old or "", row["pw_hash"]):
            raise AuthError("Your current password is incorrect.")
        if old == new:
            raise AuthError("Choose a new password that's different from the current one.")
        con.execute("UPDATE users SET pw_hash=?, must_change=0 WHERE id=?", (hash_password(new), user_id))


def finish_forced_change(user_id: int, new: str) -> None:
    check_password_strength(new)
    with db() as con:
        row = con.execute("SELECT must_change FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or not row["must_change"]:
            raise AuthError("No password change is required.")
        con.execute("UPDATE users SET pw_hash=?, must_change=0 WHERE id=?", (hash_password(new), user_id))


def delete_account(user_id: int, password: str) -> None:
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or not verify_password(password or "", row["pw_hash"]):
            raise AuthError("Password is incorrect.")
        if row["role"] == "admin" and _active_admins(con) <= 1:
            raise AuthError("You're the only administrator. Make someone else an admin first.")
        _purge(con, user_id)


def _purge(con, user_id: int) -> None:
    con.execute("DELETE FROM usage WHERE user_id=?", (user_id,))
    con.execute("DELETE FROM resets WHERE user_id=?", (user_id,))
    con.execute("DELETE FROM messages WHERE user_id=?", (user_id,))
    con.execute("DELETE FROM users WHERE id=?", (user_id,))


# --------------------------------------------------------------------------- #
# Forgot password
# --------------------------------------------------------------------------- #
def smtp_configured() -> bool:
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("SMTP_FROM"))


def send_email(to: str, subject: str, body: str) -> None:
    host, port = os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", "587"))
    user, pw = os.environ.get("SMTP_USER"), os.environ.get("SMTP_PASS")
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = os.environ["SMTP_FROM"], to, subject
    msg.set_content(body)
    ctx = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=20) as s:
            if user:
                s.login(user, pw or "")
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.starttls(context=ctx)
            if user:
                s.login(user, pw or "")
            s.send_message(msg)


def _code_hash(code: str, salt: str) -> str:
    return hmac.new(bytes.fromhex(salt), code.encode(), hashlib.sha256).hexdigest()


def request_reset(email: str) -> str:
    """Always returns 'ok' (never reveals whether the account exists). Returns 'email' or 'admin' as mode."""
    email = norm_email(email)
    mode = "email" if smtp_configured() else "admin"
    code = None
    site = get_setting("site_name")
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if row is None or row["status"] != "active":
            return mode
        recent = con.execute("SELECT COUNT(*) FROM resets WHERE user_id=? AND created_at>?",
                             (row["id"], now() - 3600)).fetchone()[0]
        if recent >= 3:
            return mode
        if mode == "email":
            code = f"{secrets.randbelow(10 ** 6):06d}"
            salt = secrets.token_hex(8)
            con.execute("INSERT INTO resets(user_id,via,code_hash,expires,created_at) VALUES(?,?,?,?,?)",
                        (row["id"], "email", f"{salt}${_code_hash(code, salt)}", now() + CODE_MINUTES * 60, now()))
        else:
            con.execute("INSERT INTO resets(user_id,via,created_at) VALUES(?,?,?)", (row["id"], "admin", now()))
    if code:
        try:
            send_email(email, f"{site} password reset code",
                       f"Your {site} password reset code is: {code}\n\nIt expires in {CODE_MINUTES} minutes. "
                       "If you didn't ask for this, you can ignore this email.")
        except Exception:
            pass  # don't leak delivery problems to the requester
    return mode


def complete_reset(email: str, code: str, new_password: str) -> None:
    check_password_strength(new_password)
    bad = AuthError("That code is invalid or has expired. Request a new one.")
    with db() as con:
        u = con.execute("SELECT id FROM users WHERE email=?", (norm_email(email),)).fetchone()
        if not u:
            raise bad
        r = con.execute("SELECT * FROM resets WHERE user_id=? AND via='email' AND used=0 AND expires>? "
                        "ORDER BY id DESC LIMIT 1", (u["id"], now())).fetchone()
        if not r or r["attempts"] >= MAX_CODE_TRIES:
            raise bad
        salt, h = r["code_hash"].split("$")
        if not hmac.compare_digest(_code_hash((code or "").strip(), salt), h):
            con.execute("UPDATE resets SET attempts=attempts+1 WHERE id=?", (r["id"],))
            con.commit()
            raise bad
        con.execute("UPDATE users SET pw_hash=?, fails=0, locked_until=0, must_change=0 WHERE id=?",
                    (hash_password(new_password), u["id"]))
        con.execute("UPDATE resets SET used=1 WHERE user_id=?", (u["id"],))


def pending_admin_resets() -> list[dict]:
    with db() as con:
        rows = con.execute("SELECT r.id AS reset_id, u.id AS user_id, u.email, u.name, r.created_at "
                           "FROM resets r JOIN users u ON u.id=r.user_id "
                           "WHERE r.via='admin' AND r.handled=0 ORDER BY r.id DESC").fetchall()
    return [dict(r) for r in rows]


def dismiss_reset(reset_id: int) -> None:
    with db() as con:
        con.execute("UPDATE resets SET handled=1 WHERE id=?", (reset_id,))


def issue_temp_password(user_id: int) -> str:
    """Admin action: set a random one-time password; user must change it at next sign-in."""
    temp = secrets.token_urlsafe(9) + "7a"
    with db() as con:
        if not con.execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone():
            raise AuthError("User not found.")
        con.execute("UPDATE users SET pw_hash=?, must_change=1, fails=0, locked_until=0 WHERE id=?",
                    (hash_password(temp), user_id))
        con.execute("UPDATE resets SET handled=1 WHERE user_id=? AND via='admin'", (user_id,))
    return temp


# --------------------------------------------------------------------------- #
# Usage, contact messages
# --------------------------------------------------------------------------- #
def record_usage(user_id: int | None, tool: str, saved: int = 0) -> None:
    try:
        with db() as con:
            con.execute("INSERT INTO usage(user_id,tool,saved,ts) VALUES(?,?,?,?)",
                        (user_id, tool[:60], int(saved or 0), now()))
    except Exception:
        pass


def user_usage_count(user_id: int) -> int:
    with db() as con:
        return con.execute("SELECT COUNT(*) FROM usage WHERE user_id=?", (user_id,)).fetchone()[0]


def add_message(name: str, email: str, subject: str, body: str, user_id: int | None = None) -> None:
    name, email, subject, body = (name or "").strip(), norm_email(email), (subject or "").strip(), (body or "").strip()
    if not 2 <= len(name) <= 60:
        raise AuthError("Enter your name.")
    if not EMAIL_RE.match(email):
        raise AuthError("Enter a valid email address so we can reply.")
    if not 10 <= len(body) <= 4000:
        raise AuthError("Your message should be between 10 and 4000 characters.")
    with db() as con:
        con.execute("INSERT INTO messages(user_id,name,email,subject,body,created_at) VALUES(?,?,?,?,?,?)",
                    (user_id, name, email, subject[:120], body, now()))


def list_messages(status: str | None = None) -> list[dict]:
    q, args = "SELECT * FROM messages", ()
    if status:
        q, args = q + " WHERE status=?", (status,)
    with db() as con:
        return [dict(r) for r in con.execute(q + " ORDER BY id DESC LIMIT 300", args).fetchall()]


def set_message_status(msg_id: int, status: str) -> None:
    with db() as con:
        con.execute("UPDATE messages SET status=? WHERE id=?", (status, msg_id))


def delete_message(msg_id: int) -> None:
    with db() as con:
        con.execute("DELETE FROM messages WHERE id=?", (msg_id,))


# --------------------------------------------------------------------------- #
# Admin: users & analytics
# --------------------------------------------------------------------------- #
def list_users(q: str = "") -> list[dict]:
    like = f"%{q.strip()}%"
    with db() as con:
        rows = con.execute(
            "SELECT u.id,u.email,u.name,u.role,u.status,u.created_at,u.last_login,"
            "(SELECT COUNT(*) FROM usage x WHERE x.user_id=u.id) AS ops FROM users u "
            "WHERE u.email LIKE ? OR u.name LIKE ? ORDER BY u.created_at DESC, u.id DESC LIMIT 500", (like, like)).fetchall()
    return [dict(r) for r in rows]


def set_status(actor_id: int, user_id: int, status: str) -> None:
    if status not in ("active", "suspended"):
        raise AuthError("Invalid status.")
    with db() as con:
        row = con.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise AuthError("User not found.")
        if actor_id == user_id and status == "suspended":
            raise AuthError("You can't suspend your own account.")
        if status == "suspended" and row["role"] == "admin" and _active_admins(con) <= 1:
            raise AuthError("That's the last active administrator.")
        con.execute("UPDATE users SET status=? WHERE id=?", (status, user_id))


def set_role(actor_id: int, user_id: int, role: str) -> None:
    if role not in ("user", "admin"):
        raise AuthError("Invalid role.")
    with db() as con:
        row = con.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise AuthError("User not found.")
        if role == "user" and row["role"] == "admin" and _active_admins(con) <= 1:
            raise AuthError("There must be at least one administrator.")
        con.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))


def admin_delete_user(actor_id: int, user_id: int) -> None:
    if actor_id == user_id:
        raise AuthError("Use the Account page to delete your own account.")
    with db() as con:
        row = con.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise AuthError("User not found.")
        if row["role"] == "admin" and _active_admins(con) <= 1:
            raise AuthError("That's the last active administrator.")
        _purge(con, user_id)


def stats() -> dict:
    t = now()
    with db() as con:
        q = lambda sql, *a: con.execute(sql, a).fetchone()[0]  # noqa: E731
        return {
            "users": q("SELECT COUNT(*) FROM users"),
            "admins": q("SELECT COUNT(*) FROM users WHERE role='admin'"),
            "suspended": q("SELECT COUNT(*) FROM users WHERE status='suspended'"),
            "new7": q("SELECT COUNT(*) FROM users WHERE created_at>?", t - 7 * 86400),
            "active24": q("SELECT COUNT(*) FROM users WHERE last_login>?", t - 86400),
            "ops": q("SELECT COUNT(*) FROM usage"),
            "ops24": q("SELECT COUNT(*) FROM usage WHERE ts>?", t - 86400),
            "saved": q("SELECT COALESCE(SUM(saved),0) FROM usage"),
            "new_msgs": q("SELECT COUNT(*) FROM messages WHERE status='new'"),
            "resets": q("SELECT COUNT(*) FROM resets WHERE via='admin' AND handled=0"),
        }


def usage_by_tool(days: int = 30) -> list[tuple[str, int]]:
    with db() as con:
        rows = con.execute("SELECT tool, COUNT(*) c FROM usage WHERE ts>? GROUP BY tool ORDER BY c DESC",
                           (now() - days * 86400,)).fetchall()
    return [(r["tool"], r["c"]) for r in rows]


def usage_per_day(days: int = 14) -> list[tuple[str, int]]:
    with db() as con:
        rows = con.execute("SELECT strftime('%Y-%m-%d', ts, 'unixepoch') d, COUNT(*) c FROM usage "
                           "WHERE ts>? GROUP BY d ORDER BY d", (now() - days * 86400,)).fetchall()
    return [(r["d"], r["c"]) for r in rows]


def recent_usage(limit: int = 100) -> list[dict]:
    with db() as con:
        rows = con.execute("SELECT x.ts, x.tool, x.saved, COALESCE(u.email,'guest') AS who FROM usage x "
                           "LEFT JOIN users u ON u.id=x.user_id ORDER BY x.id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
