#!/usr/bin/env python3
import os
import re
import time
import ssl
import imaplib
import smtplib
import email
import yaml
import hashlib
import datetime as dt
import socket
import select

from email import policy
from email.message import EmailMessage
from email.headerregistry import Address
from pathlib import Path

# ----------------------------
# Utilities
# ----------------------------

def env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name, default)
    return v

def now_utc() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)

def parse_bool(x, default=False):
    if x is None: return default
    if isinstance(x, bool): return x
    return str(x).strip().lower() in ("1", "true", "yes", "y", "on")

def safe_regex(pattern: str):
    return re.compile(pattern, re.IGNORECASE) if pattern else None

def addr_list(header_val: str) -> str:
    if not header_val:
        return ""
    return header_val

# ----------------------------
# Rule engine
# ----------------------------

class Rule:
    def __init__(self, spec: dict):
        self.name = spec.get("name", "unnamed")
        cond = spec.get("if", {}) or {}
        self.from_regex = safe_regex(cond.get("from_regex", ""))
        self.subject_regex = safe_regex(cond.get("subject_regex", ""))
        self.body_regex = safe_regex(cond.get("body_regex", ""))
        self.to_regex = safe_regex(cond.get("to_regex", ""))

        action = spec.get("action", {})
        if isinstance(action, str):
            # shorthand: "drop"
            action = {"type": action}
        self.action_type = action.get("type", "forward")  # forward | drop
        self.forward_to = action.get("forward_to", [])
        self.subject_prefix = action.get("subject_prefix", "")
        self.add_headers = action.get("add_headers", {}) or {}

    def matches(self, msg: email.message.Message, body_cache: dict) -> bool:
        if self.from_regex and not self.from_regex.search(addr_list(msg.get("From", ""))):
            return False
        if self.to_regex and not self.to_regex.search(addr_list(msg.get("To", ""))):
            return False
        if self.subject_regex and not self.subject_regex.search(msg.get("Subject", "") or ""):
            return False
        if self.body_regex:
            body = body_cache.get("body")
            if body is None:
                body = get_text_body(msg)
                body_cache["body"] = body
            if not self.body_regex.search(body or ""):
                return False
        return True

# ----------------------------
# Dedup & rate limit
# ----------------------------

class Mitigator:
    def __init__(self, spec: dict):
        self.window = int(spec.get("deduplicate_window_seconds", 0))
        self.dedupe_by = spec.get("deduplicate_by", ["From", "Subject"])
        self.rate_cap = int(spec.get("max_messages_per_minute", 0))
        self._seen = {}  # hash -> timestamp
        self._bucket = []  # timestamps of sends in last minute

    def dedupe_key(self, msg: email.message.Message) -> str:
        parts = []
        for h in self.dedupe_by:
            parts.append(msg.get(h, ""))
        h = hashlib.sha256("||".join(parts).encode()).hexdigest()
        return h

    def allow(self, msg: email.message.Message) -> bool:
        t = now_utc().timestamp()
        # dedupe
        if self.window > 0:
            key = self.dedupe_key(msg)
            prev = self._seen.get(key, 0)
            if t - prev < self.window:
                return False
            self._seen[key] = t
            # cleanup old entries
            for k, v in list(self._seen.items()):
                if t - v > self.window:
                    self._seen.pop(k, None)
        # rate limit
        if self.rate_cap > 0:
            self._bucket.append(t)
            one_min_ago = t - 60
            self._bucket = [x for x in self._bucket if x >= one_min_ago]
            if len(self._bucket) > self.rate_cap:
                return False
        return True

# ----------------------------
# Mailer / IMAP
# ----------------------------

import ssl
from email.message import EmailMessage
from pathlib import Path

def _make_ssl_context(ca_file: str | None) -> ssl.SSLContext:
    """
    Create an SSLContext that loads a CA from either PEM (path) or DER (bytes).
    """
    ctx = ssl.create_default_context()
    if not ca_file:
        return ctx

    data = Path(ca_file).read_bytes()
    # Try PEM first (path), otherwise load DER as cadata
    if data.lstrip().startswith(b"-----BEGIN "):
        ctx.load_verify_locations(cafile=ca_file)
    else:
        ctx.load_verify_locations(cadata=data)
    return ctx

def _get_text_body(msg) -> str:
    """
    Extract a readable text body from an email.message.Message.
    Safe for both multipart and single-part mails.
    """
    import email
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get_content_disposition()
            if ctype == "text/plain" and disp != "attachment":
                try:
                    return part.get_content()
                except Exception:
                    return part.get_payload(decode=True).decode(errors="ignore")
        # fallback
        try:
            return msg.get_body(preferencelist=("plain", "html")).get_content()
        except Exception:
            return msg.as_string()
    else:
        try:
            return msg.get_content()
        except Exception:
            return msg.get_payload(decode=True).decode(errors="ignore")


class SmtpSender:
    """
    SMTP sender with STARTTLS + custom CA and strict fully-qualified From handling.

    Expected config keys under `smtp`:
      server: SMTP hostname (e.g., "mail.i.cz")
      port:   587 (default)
      starttls: true|false (default: true)
      username: SMTP auth user (e.g., "xgov.alerts")
      password_env: ENV var name holding the password (default: ALERTS_PASS)
      from_addr: "xgov.alerts@i.cz"  (RECOMMENDED)
      domain: "i.cz"                  (used only if from_addr missing; builds username@domain)
      display_name: "XGov Alerts"     (optional)
      reply_to: "noc@i.cz"            (optional)
    """

    def __init__(self, cfg: dict, ca_file: str | None = None, env_getter=None):
        import os
        import smtplib
        self._smtplib = smtplib
        self._env = env_getter or os.getenv

        self.server = cfg.get("server", "mail.i.cz")
        self.port = int(cfg.get("port", 587))
        self.starttls = str(cfg.get("starttls", True)).lower() in ("1", "true", "yes", "on")
        self.username = cfg.get("username", "")

        # Build/validate fully-qualified From:
        domain = cfg.get("domain")
        self.from_addr = cfg.get("from_addr") or (f"{self.username}@{domain}" if domain else self.username)
        if "@" not in self.from_addr:
            raise RuntimeError("smtp.from_addr must be a fully-qualified email address (user@domain)")

        self.display_name = cfg.get("display_name")
        self.reply_to = cfg.get("reply_to")

        pw_env = cfg.get("password_env") or "ALERTS_PASS"
        self.password = self._env(pw_env)
        if not self.password:
            raise RuntimeError(f"Env variable {pw_env} not set for SMTP password")

        # TLS context (accept PEM or DER CA)
        self.context = _make_ssl_context(ca_file)

    def _header_from(self) -> str:
        return f'{self.display_name} <{self.from_addr}>' if self.display_name else self.from_addr

    def send_forward(self,
                     original_msg,
                     to_list: list[str],
                     subject_prefix: str = "",
                     add_headers: dict | None = None):
        """
        Forward an email:
          - plain text body extracted + original attached as message/rfc822
          - From/Envelope sender = fully qualified address
        """
        if not to_list:
            return

        fwd = EmailMessage()
        subj = original_msg.get("Subject", "(no subject)")
        fwd["Subject"] = f"{subject_prefix}{subj}" if subject_prefix else subj
        fwd["From"] = self._header_from()
        fwd["To"] = ", ".join(to_list)
        if self.reply_to:
            fwd["Reply-To"] = self.reply_to

        # Preserve some original headers for traceability
        fwd["X-Original-From"] = original_msg.get("From", "")
        fwd["X-Original-To"] = original_msg.get("To", "")
        fwd["X-Original-Date"] = original_msg.get("Date", "")

        if add_headers:
            for k, v in add_headers.items():
                fwd[k] = v

        # Body + attach full original
        fwd.set_content(_get_text_body(original_msg))
        try:
            fwd.add_attachment(
                original_msg.as_bytes(),
                maintype="message",
                subtype="rfc822",
                filename="original.eml"
            )
        except Exception:
            # If as_bytes() fails, fall back to no attachment (rare)
            pass

        with self._smtplib.SMTP(self.server, self.port, timeout=60) as s:
            if self.starttls:
                s.starttls(context=self.context)
            s.login(self.username, self.password)
            # envelope sender must be fully-qualified
            print(f"SMTP using envelope From: {self.from_addr}")
            s.send_message(fwd, from_addr=self.from_addr, to_addrs=to_list)

class ImapClient:
    def __init__(self, cfg, ca_file=None):
        self.server = cfg.get("server", "mail.i.cz")
        self.port = int(cfg.get("port", 993))
        self.ssl = parse_bool(cfg.get("ssl", True))
        self.username = cfg.get("username", "")
        pw_env = cfg.get("password_env") or "ALERTS_PASS"
        self.password = env(pw_env)
        if not self.password:
            raise RuntimeError(f"Env variable {pw_env} not set for IMAP password")
        self.mailbox = cfg.get("mailbox", "INBOX")
        self.poll_seconds = int(cfg.get("poll_seconds", 20))
        self.use_idle = parse_bool(cfg.get("idle", True))
        self.post = cfg.get("post_process", {}) or {}

        # SSL context with custom CA
        self.context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()

    def _connect(self) -> imaplib.IMAP4:
        if self.ssl:
            imap = imaplib.IMAP4_SSL(self.server, self.port, ssl_context=self.context)
        else:
            imap = imaplib.IMAP4(self.server, self.port)
        imap.login(self.username, self.password)
        imap.select(self.mailbox)
        return imap

    def _apply_postprocess(self, imap: imaplib.IMAP4, msg_id: bytes):
        if self.post.get("delete"):
            imap.store(msg_id, "+FLAGS", r"(\Deleted)")
            imap.expunge()
            return
        if self.post.get("mark_seen", True):
            imap.store(msg_id, "+FLAGS", r"(\Seen)")
        move_to = self.post.get("move_to")
        if move_to:
            # COPY then delete
            imap.copy(msg_id, move_to)
            imap.store(msg_id, "+FLAGS", r"(\Deleted)")
            imap.expunge()

    def fetch_unseen(self, handler):
        imap = self._connect()
        try:
            typ, data = imap.search(None, "UNSEEN")
            if typ != "OK":
                return
            for num in data[0].split():
                typ, msg_data = imap.fetch(num, "(RFC822)")
                if typ != "OK" or not msg_data:
                    continue
                raw = msg_data[0][1]
                msg = email.message_from_bytes(raw, policy=policy.default)
                sent_or_dropped = handler(msg)
                if sent_or_dropped:
                    self._apply_postprocess(imap, num)
                else:
                    # avoid hot-loop on a problematic message
                    time.sleep(self.poll_seconds)
        finally:
            try:
                imap.close()
            except Exception:
                pass
            imap.logout()

    def idle_loop(self, handler):
        """Idle if possible; otherwise poll, with low CPU usage."""
        backoff = self.poll_seconds
        while True:
            try:
                if not self.use_idle:
                    raise RuntimeError("IDLE disabled")

                imap = self._connect()
                # enter IDLE
                tag = imap._new_tag()
                imap.send(f"{tag} IDLE\r\n".encode())

                start = time.time()
                while time.time() - start < 29 * 60:  # refresh before 30m
                    # block until there is data, otherwise just continue idling
                    r, _, _ = select.select([imap.sock], [], [], self.poll_seconds)
                    if not r:
                        continue
                    try:
                        resp = imap.readline()
                        print("IMAP IDLE response:", resp)
                        if resp and (b"EXISTS" in resp or b"RECENT" in resp):
                            # end IDLE, fetch unseen, re-enter IDLE
                            imap.send(b"DONE\r\n")
                            try:
                                imap.sock.settimeout(5)
                                imap.readline()  # read completion
                            except Exception:
                                pass
                            self.fetch_unseen(handler)
                            tag = imap._new_tag()
                            imap.send(f"{tag} IDLE\r\n".encode())
                    except (TimeoutError, socket.timeout, OSError):
                        # benign timeout/no data; keep idling
                        continue

                # exit IDLE cleanly
                try:
                    imap.send(b"DONE\r\n")
                    imap.sock.settimeout(5)
                    imap.readline()
                except Exception:
                    pass
                imap.logout()
                backoff = self.poll_seconds  # reset backoff on success

            except Exception as e:
                print(f"IDLE error {type(e).__name__}: {e}; backing off {backoff}s then polling once")
                time.sleep(backoff)
                self.fetch_unseen(handler)
                backoff = min(backoff * 2, 60)  # cap backoff at 60s

# ----------------------------
# Orchestrator
# ----------------------------

class App:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        ca_file = cfg.get("tls", {}).get("ca_file")
        self.smtp = SmtpSender(cfg.get("smtp", {}), ca_file=ca_file)
        self.imap = ImapClient(cfg.get("imap", {}), ca_file=ca_file)
        self.defaults = cfg.get("forward_defaults", {}) or {}
        self.default_to = self.defaults.get("to", [])
        self.default_prefix = self.defaults.get("subject_prefix", "")
        self.rules = [Rule(r) for r in (cfg.get("rules") or [])]
        self.mitigator = Mitigator(cfg.get("mitigations", {}) or {})

    def decide(self, msg: email.message.Message) -> dict:
        """Return action dict: {type: 'drop'|'forward', to: [...], prefix: str, headers: {...}}"""
        body_cache = {}
        for r in self.rules:
            try:
                if r.matches(msg, body_cache):
                    if r.action_type == "drop":
                        return {"type": "drop"}
                    else:
                        to_list = r.forward_to or self.default_to
                        return {
                            "type": "forward",
                            "to": to_list,
                            "prefix": r.subject_prefix or self.default_prefix,
                            "headers": r.add_headers,
                        }
            except Exception:
                # a broken rule shouldn't crash the app; continue
                continue
        # default action: forward to default_to if configured, otherwise drop
        if self.default_to:
            return {"type": "forward", "to": self.default_to, "prefix": self.default_prefix, "headers": {}}
        return {"type": "drop"}

    def handle_message(self, msg: email.message.Message) -> bool:
        print(f"Received message from {msg.get('From')} with subject {msg.get('Subject')}")
        # mitigations first
        if not self.mitigator.allow(msg):
            return False
        decision = self.decide(msg)
        if decision["type"] == "drop":
            return False
        to_list = decision["to"]
        if not to_list:
            return False
        self.smtp.send_forward(
            original=msg,
            to_list=to_list,
            subject_prefix=decision.get("prefix", ""),
            add_headers=decision.get("headers", {}),
        )
        return True

    def run(self):
        prefer_idle = parse_bool(self.cfg.get("imap", {}).get("idle", True))
        if prefer_idle:
            self.imap.idle_loop(self.handle_message)
        else:
            while True:
                self.imap.fetch_unseen(self.handle_message)
                time.sleep(self.imap.poll_seconds)

# ----------------------------
# Entry
# ----------------------------

def main():
    import argparse
    ap = argparse.ArgumentParser(description="IMAP listener that resends mail via SMTP with rules.")
    ap.add_argument("-c", "--config", default="config.yaml", help="Path to YAML config")
    args = ap.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    app = App(cfg)
    app.run()

if __name__ == "__main__":
    main()
