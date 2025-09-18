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

from email import policy
from email.message import EmailMessage
from email.headerregistry import Address

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

def get_text_body(msg: email.message.Message) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get_content_disposition()
            if ctype == "text/plain" and disp != "attachment":
                try:
                    return part.get_content()
                except Exception:
                    return part.get_payload(decode=True).decode(errors="ignore")
        # fallback to first part
        try:
            return msg.get_body(preferencelist=("plain", "html")).get_content()
        except Exception:
            return msg.as_string()
    else:
        try:
            return msg.get_content()
        except Exception:
            return msg.get_payload(decode=True).decode(errors="ignore")

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

class SmtpSender:
    def __init__(self, cfg, ca_file=None):
        self.server = cfg.get("server", "mail.i.cz")
        self.port = int(cfg.get("port", 587))
        self.starttls = parse_bool(cfg.get("starttls", True))
        self.username = cfg.get("username", "")
        self.from_addr = cfg.get("from_addr", self.username)
        # If username has no '@' and from_addr missing, derive domain from server (mail.i.cz -> i.cz)
        if "@" not in self.from_addr:
            parts = self.server.split(".")
            domain = ".".join(parts[1:]) if len(parts) > 1 else ""
            if domain:
                self.from_addr = f"{self.from_addr}@{domain}"
        pw_env = cfg.get("password_env") or "ALERTS_PASS"
        self.password = env(pw_env)
        if not self.password:
            raise RuntimeError(f"Env variable {pw_env} not set for SMTP password")

        # TLS context with custom CA
        self.context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()

    def send_forward(self, original, to_list, subject_prefix="", add_headers=None):
        if not to_list:
            return
        fwd = EmailMessage()
        subj = original.get("Subject", "(no subject)")
        fwd["Subject"] = f"{subject_prefix}{subj}" if subject_prefix else subj
        fwd["From"] = self.from_addr
        fwd["To"] = ", ".join(to_list)
        fwd["X-Original-From"] = original.get("From", "")
        fwd["X-Original-To"] = original.get("To", "")
        fwd["X-Original-Date"] = original.get("Date", "")
        if add_headers:
            for k, v in add_headers.items():
                fwd[k] = v

        # Body + original as rfc822 attachment
        fwd.set_content(get_text_body(original))
        fwd.add_attachment(original.as_bytes(), maintype="message", subtype="rfc822", filename="original.eml")

        with smtplib.SMTP(self.server, self.port, timeout=60) as s:
            if self.starttls:
                s.starttls(context=self.context)
            s.login(self.username, self.password)
            # IMPORTANT: set the envelope sender explicitly
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
        """Fetch unseen messages and call handler(msg) -> bool (sent or dropped)."""
        imap = self._connect()
        try:
            typ, data = imap.search(None, "UNSEEN")
            print("IMAP search response:", typ, data)
            if typ != "OK":
                return
            for num in data[0].split():
                typ, msg_data = imap.fetch(num, "(RFC822)")
                if typ != "OK" or not msg_data:
                    continue
                raw = msg_data[0][1]
                msg = email.message_from_bytes(raw, policy=policy.default)
                sent_or_dropped = handler(msg)
                # post-process regardless if sent or dropped (you can adjust behavior in handler if needed)
                self._apply_postprocess(imap, num)
        finally:
            try:
                imap.close()
            except Exception:
                pass
            imap.logout()

    def idle_loop(self, handler):
        """Idle if possible; otherwise poll."""
        while True:
            try:
                if not self.use_idle:
                    raise RuntimeError("IDLE disabled")
                imap = self._connect()
                # Enter IDLE
                tag = imap._new_tag()
                imap.send(f"{tag} IDLE\r\n".encode())

                start = time.time()
                while time.time() - start < 29 * 60:  # keep IDLE < 30 min
                    imap.sock.settimeout(self.poll_seconds)
                    try:
                        resp = imap.readline()
                        print("IMAP IDLE response:", resp)
                        if not resp:
                            # treat empty read as timeout-equivalent; continue
                            continue
                        if b"EXISTS" in resp or b"RECENT" in resp:
                            # End IDLE to fetch
                            imap.send(b"DONE\r\n")
                            # read the completion response (ignore content)
                            try:
                                imap.sock.settimeout(5)
                                imap.readline()
                            except Exception:
                                pass
                            self.fetch_unseen(handler)
                            # Re-enter IDLE
                            tag = imap._new_tag()
                            imap.send(f"{tag} IDLE\r\n".encode())
                    except (TimeoutError, socket.timeout, OSError):
                        # benign: no activity within timeout window — just continue IDLE
                        continue

                # exit IDLE cleanly every ~29 min
                try:
                    imap.send(b"DONE\r\n")
                    imap.sock.settimeout(5)
                    imap.readline()
                except Exception:
                    pass
                imap.logout()

            except Exception as e:
                # fallback to polling if IDLE fails for any reason
                print(f"IDLE error {type(e).__name__}: {e}; falling back to poll")
                self.fetch_unseen(handler)
                time.sleep(self.poll_seconds)

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
