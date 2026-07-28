#!/usr/bin/env python3
"""
SaveMyMind — a personal, local knowledge base of vulnerability-triage decisions.

Every record carries a STATUS (false positive, not a false positive, waiver),
an optional EXPIRY date, and a full change HISTORY. It runs from a single file,
stores everything in one local SQLite database, and serves a browser GUI.

Run it:

    python savemymind.py

No external dependencies (Python 3.8+ standard library only). The server binds
to localhost only, so nothing is exposed on your network.

License: MIT.
"""

import argparse
import csv
import io
import json
import os
import re
import sqlite3
import sys
import threading
import webbrowser
from collections import Counter
from datetime import datetime, date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from xml.sax.saxutils import escape as xml_escape

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "savemymind.db")

DATA_FIELDS = ("package", "cve", "cpe", "sha1", "file_path", "author", "description")
REQUIRED = ("cve",)
TRACK_FIELDS = DATA_FIELDS + ("stato", "expires_at")

VALID_STATI = ("falso_positivo", "non_falso_positivo", "deroga")
DEFAULT_STATO = "falso_positivo"
SUPPRESSIBLE = ("falso_positivo", "deroga")
DEFAULT_LIMIT = 25
EXPIRY_SOON_DAYS = 30

SUPPRESSION_NS = "https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd"
UNTIL_PLACEHOLDER = "AAAA-MM-GGZ"

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    package     TEXT NOT NULL,
    cve         TEXT NOT NULL,
    cpe         TEXT NOT NULL,
    stato       TEXT NOT NULL DEFAULT 'falso_positivo',
    expires_at  TEXT,
    sha1        TEXT,
    file_path   TEXT,
    author      TEXT,
    description TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT
);
CREATE TABLE IF NOT EXISTS history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id   INTEGER NOT NULL,
    changed_at TEXT NOT NULL,
    field      TEXT NOT NULL,
    old_value  TEXT,
    new_value  TEXT
);
"""


def connect(db_path):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.executescript(SCHEMA)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(entries)")}
    if "stato" not in cols:
        conn.execute("ALTER TABLE entries ADD COLUMN stato TEXT NOT NULL DEFAULT 'falso_positivo'")
    if "expires_at" not in cols:
        conn.execute("ALTER TABLE entries ADD COLUMN expires_at TEXT")
    conn.commit()
    return conn


def row_to_dict(row):
    return {k: row[k] for k in row.keys()}


def norm_stato(value):
    v = (value or "").strip().lower()
    return v if v in VALID_STATI else DEFAULT_STATO


def get_entry(conn, entry_id):
    r = conn.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    return row_to_dict(r) if r else None


# ---------------------------------------------------------------------------
# Filtering / listing
# ---------------------------------------------------------------------------


def has_filters(filters):
    keys = ("package", "cve", "cpe", "sha1", "file_path", "author",
            "stato", "q", "date_from", "date_to", "expiry")
    return any((filters.get(k) or "").strip() for k in keys)


def _build_where(filters):
    where, params = [], []
    for key in ("package", "cve", "cpe", "sha1", "file_path", "author"):
        val = (filters.get(key) or "").strip()
        if val:
            where.append(f"{key} LIKE ?")
            params.append(f"%{val}%")
    stato = (filters.get("stato") or "").strip().lower()
    if stato in VALID_STATI:
        where.append("stato = ?")
        params.append(stato)
    date_from = (filters.get("date_from") or "").strip()
    if date_from:
        where.append("date(created_at) >= date(?)")
        params.append(date_from)
    date_to = (filters.get("date_to") or "").strip()
    if date_to:
        where.append("date(created_at) <= date(?)")
        params.append(date_to)
    expiry = (filters.get("expiry") or "").strip().lower()
    if expiry == "expired":
        where.append("expires_at IS NOT NULL AND expires_at != '' AND date(expires_at) < date('now')")
    elif expiry == "soon":
        where.append("expires_at IS NOT NULL AND expires_at != '' AND date(expires_at) >= date('now') AND date(expires_at) <= date('now', ?)")
        params.append(f"+{EXPIRY_SOON_DAYS} day")
    elif expiry == "active":
        where.append("expires_at IS NOT NULL AND expires_at != '' AND date(expires_at) >= date('now')")
    q = (filters.get("q") or "").strip()
    if q:
        clause = " OR ".join(f"{c} LIKE ?" for c in DATA_FIELDS)
        where.append(f"({clause})")
        params.extend([f"%{q}%"] * len(DATA_FIELDS))
    return (" WHERE " + " AND ".join(where)) if where else "", params


def count_entries(conn, filters):
    where_sql, params = _build_where(filters)
    return conn.execute("SELECT COUNT(*) AS n FROM entries" + where_sql, params).fetchone()["n"]


def list_entries(conn, filters, limit=None):
    where_sql, params = _build_where(filters)
    sql = "SELECT * FROM entries" + where_sql
    sql += " ORDER BY datetime(COALESCE(updated_at, created_at)) DESC, id DESC"
    if limit is not None:
        sql += " LIMIT ?"
        params = params + [int(limit)]
    return [row_to_dict(r) for r in conn.execute(sql, params).fetchall()]


def expiring_entries(conn):
    soon = (date.today() + timedelta(days=EXPIRY_SOON_DAYS)).isoformat()
    rows = conn.execute(
        "SELECT * FROM entries WHERE expires_at IS NOT NULL AND expires_at != '' "
        "AND stato IN ('falso_positivo','deroga') AND date(expires_at) <= date(?) "
        "ORDER BY date(expires_at) ASC", (soon,)).fetchall()
    return [row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Mutations (with history) + duplicate detection
# ---------------------------------------------------------------------------


def validate(data):
    missing = [k for k in REQUIRED if not (data.get(k) or "").strip()]
    if missing:
        return f"Missing required fields: {', '.join(missing)}"
    return None


def find_duplicates(conn, data):
    rows = conn.execute(
        "SELECT * FROM entries WHERE cve = ? COLLATE NOCASE AND package = ? COLLATE NOCASE",
        ((data.get("cve") or "").strip(), (data.get("package") or "").strip())).fetchall()
    return [row_to_dict(r) for r in rows]


def _clean(data):
    out = {k: ((data.get(k) or "").strip() or None) for k in DATA_FIELDS}
    for k in ("package", "cpe"):   # optional now, but NOT NULL in older databases
        if out[k] is None:
            out[k] = ""
    out["stato"] = norm_stato(data.get("stato"))
    out["expires_at"] = (data.get("expires_at") or "").strip() or None
    return out


def log_history(conn, entry_id, field, old, new):
    conn.execute("INSERT INTO history(entry_id,changed_at,field,old_value,new_value) VALUES(?,?,?,?,?)",
                 (entry_id, datetime.now().isoformat(timespec="seconds"), field, old, new))


def create_entry(conn, data):
    now = datetime.now().isoformat(timespec="seconds")
    vals = _clean(data)
    cols = list(vals.keys()) + ["created_at", "updated_at"]
    params = list(vals.values()) + [now, now]
    conn.execute(f"INSERT INTO entries({','.join(cols)}) VALUES({','.join('?'*len(cols))})", params)
    eid = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    log_history(conn, eid, "created", None, vals["stato"])
    conn.commit()
    return eid


def update_entry(conn, entry_id, data):
    old = get_entry(conn, entry_id)
    if not old:
        return 0
    now = datetime.now().isoformat(timespec="seconds")
    vals = _clean(data)
    assignments = ",".join(f"{k}=?" for k in vals) + ",updated_at=?"
    params = list(vals.values()) + [now, entry_id]
    conn.execute(f"UPDATE entries SET {assignments} WHERE id=?", params)
    for k in TRACK_FIELDS:
        if (old.get(k) or None) != (vals.get(k) or None):
            log_history(conn, entry_id, k, old.get(k), vals.get(k))
    conn.commit()
    return 1


def delete_entry(conn, entry_id):
    cur = conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
    conn.execute("DELETE FROM history WHERE entry_id=?", (entry_id,))
    conn.commit()
    return cur.rowcount


def get_history(conn, entry_id):
    rows = conn.execute("SELECT * FROM history WHERE entry_id=? ORDER BY id DESC", (entry_id,)).fetchall()
    return [row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def stats(conn):
    rows = list_entries(conn, {})
    today = date.today().isoformat()
    soon = (date.today() + timedelta(days=EXPIRY_SOON_DAYS)).isoformat()
    by_stato = {s: 0 for s in VALID_STATI}
    cves, packages = Counter(), Counter()
    expired = expiring = 0
    for r in rows:
        st = norm_stato(r.get("stato"))
        by_stato[st] = by_stato.get(st, 0) + 1
        if r.get("cve"):
            cves[r["cve"]] += 1
        if r.get("package"):
            packages[r["package"]] += 1
        exp = r.get("expires_at")
        if exp and st in SUPPRESSIBLE:
            if exp < today:
                expired += 1
            elif exp <= soon:
                expiring += 1
    return {
        "total": len(rows),
        "by_stato": by_stato,
        "expired": expired,
        "expiring": expiring,
        "top_cve": cves.most_common(6),
        "top_package": packages.most_common(6),
    }


# ---------------------------------------------------------------------------
# Suppression XML (single entry) + data export (CSV / JSON / XML)
# ---------------------------------------------------------------------------


def purl_to_regex(package):
    base = package.split("@", 1)[0] if "@" in package else package
    esc = re.escape(base)
    return f"^{esc}@.*$" if "@" in package else f"^{esc}.*$"


def suppress_block(entry):
    stato = norm_stato(entry.get("stato"))
    if stato not in SUPPRESSIBLE:
        return None
    exp = (entry.get("expires_at") or "").strip()
    if exp:
        until = f' until="{exp}Z"'
    elif stato == "deroga":
        until = f' until="{UNTIL_PLACEHOLDER}"'
    else:
        until = ""
    note = (entry.get("description") or "").strip() or "(no reason recorded)"
    lines = [f'  <suppress{until}>', f'    <notes>{xml_escape(note)}</notes>']
    pkg = (entry.get("package") or "").strip()
    if pkg:
        lines.append(f'    <packageUrl regex="true">{xml_escape(purl_to_regex(pkg))}</packageUrl>')
    vid = (entry.get("cve") or "").strip()
    if vid.upper().startswith("CVE-"):
        lines.append(f'    <cve>{xml_escape(vid)}</cve>')
    else:
        lines.append(f'    <vulnerabilityName>{xml_escape(vid)}</vulnerabilityName>')
    lines.append('  </suppress>')
    return "\n".join(lines)


def suppression_xml(entries):
    blocks = [b for b in (suppress_block(e) for e in entries) if b]
    out = ['<?xml version="1.0" encoding="UTF-8"?>', f'<suppressions xmlns="{SUPPRESSION_NS}">']
    if any(norm_stato(e.get("stato")) == "deroga" and not (e.get("expires_at") or "").strip() for e in entries):
        out.append(f'  <!-- Replace {UNTIL_PLACEHOLDER} with a real date (keep the trailing Z). -->')
    out.extend(blocks or ['  <!-- no suppressible entry -->'])
    out.append('</suppressions>')
    return "\n".join(out) + "\n"


EXPORT_COLS = ("id",) + DATA_FIELDS + ("stato", "expires_at", "created_at", "updated_at")


def _localname(tag):
    return tag.split("}", 1)[-1]


def _classify_status(text):
    """Guess the status from free text (notes + nearby comment), IT and EN."""
    t = (text or "").lower()
    not_fp = ["non falso positivo", "not a false positive", "true positive",
              "real vulnerability", "vulnerabilita reale", "vulnerabilità reale",
              "do not suppress", "non sopprimere", "must fix", "da correggere",
              "confirmed vulnerable", "reale e sfruttabile"]
    waiver = ["deroga", "waiver", "rischio accettato", "accepted risk",
              "risk accepted", "accept the risk", "risk acceptance", "eccezione",
              "in attesa di fix", "in attesa di patch", "grace period", "accettato temporaneamente"]
    fp = ["falso positivo", "false positive", "non applicabile", "not applicable",
          "non sfruttabile", "not exploitable", "non raggiungibile", "not reachable",
          "unreachable", "over-match", "overmatch", "cpe over", "cpe mismatch"]
    for kw in not_fp:
        if kw in t:
            return "non_falso_positivo"
    for kw in waiver:
        if kw in t:
            return "deroga"
    if re.search(r"\bwv\b", t) or re.search(r"\bderoga\b", t):
        return "deroga"
    for kw in fp:
        if kw in t:
            return "falso_positivo"
    if re.search(r"\bfp\b", t):
        return "falso_positivo"
    return None


def parse_import(xml_text):
    """Parse a Dependency-Check suppression file into entry dicts.
    Status is guessed from the notes and the comment just before each block;
    when nothing is found it defaults to false positive. The until attribute is
    imported as the expiry date but is not used to decide the status.
    Returns (entries, skipped_no_id) or None if the XML can't be read."""
    import xml.etree.ElementTree as ET
    try:
        parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
        root = ET.fromstring(xml_text or "", parser=parser)
    except (ET.ParseError, TypeError):
        try:
            root = ET.fromstring(xml_text or "")
        except ET.ParseError:
            return None
    entries, skipped = [], 0

    def is_comment(el):
        return el.tag is ET.Comment

    def name_of(el):
        return el.tag.split("}", 1)[-1] if isinstance(el.tag, str) else ""

    def emit(sup, comment):
        nonlocal skipped
        until = sup.get("until") or ""
        m = re.match(r"(\d{4}-\d{2}-\d{2})", until)
        exp = m.group(1) if m else ""
        pkg = gav = cpe = sha1 = fpath = notes = ""
        ids = []
        for ch in sup:
            if is_comment(ch):
                continue
            lt = name_of(ch)
            txt = " ".join("".join(ch.itertext()).split())
            if lt == "packageUrl" and not pkg:
                pkg = txt
            elif lt == "gav" and not gav:
                gav = txt
            elif lt == "cpe" and not cpe:
                cpe = txt
            elif lt == "sha1" and not sha1:
                sha1 = txt
            elif lt == "filePath" and not fpath:
                fpath = txt
            elif lt == "notes":
                notes = txt
            elif lt in ("cve", "vulnerabilityName") and txt:
                ids.append(txt)
        if not ids:
            skipped += 1
            return
        stato = _classify_status(notes + " " + (comment or "")) or "falso_positivo"
        package = pkg or gav
        for vid in ids:
            entries.append({"package": package, "cve": vid, "cpe": cpe, "sha1": sha1,
                            "file_path": fpath, "author": None, "description": notes,
                            "stato": stato, "expires_at": exp})

    def walk(parent):
        last_comment = ""
        for child in parent:
            if is_comment(child):
                last_comment = child.text or ""
                continue
            if name_of(child) == "suppress":
                emit(child, last_comment)
                last_comment = ""
            else:
                walk(child)

    walk(root)
    return entries, skipped


def export_bytes(rows, fmt):
    if fmt == "json":
        return json.dumps(rows, indent=2).encode("utf-8"), "application/json"
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(EXPORT_COLS)
        for r in rows:
            w.writerow(["" if r.get(c) is None else r.get(c) for c in EXPORT_COLS])
        return buf.getvalue().encode("utf-8"), "text/csv"
    out = ['<?xml version="1.0" encoding="UTF-8"?>', "<entries>"]
    for r in rows:
        out.append("  <entry>")
        for c in EXPORT_COLS:
            v = "" if r.get(c) is None else str(r.get(c))
            out.append(f"    <{c}>{xml_escape(v)}</{c}>")
        out.append("  </entry>")
    out.append("</entries>")
    return ("\n".join(out) + "\n").encode("utf-8"), "application/xml"


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------


def make_handler(conn):

    class Handler(BaseHTTPRequestHandler):
        server_version = "SaveMyMind"

        def log_message(self, *a):
            pass

        def _send(self, code, body=b"", ctype="application/json; charset=utf-8", extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _json(self, code, obj, extra=None):
            self._send(code, json.dumps(obj).encode("utf-8"), extra=extra)

        def _read_json(self):
            n = int(self.headers.get("Content-Length") or 0)
            if not n:
                return {}
            try:
                return json.loads(self.rfile.read(n).decode("utf-8"))
            except json.JSONDecodeError:
                return None

        def _id(self, path):
            try:
                return int(path.rstrip("/").split("/")[-1])
            except (ValueError, IndexError):
                return None

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            qs = {k: (v[0] if v else "") for k, v in parse_qs(parsed.query).items()}
            if path in ("/", "/index.html"):
                self._send(200, INDEX_HTML.encode("utf-8"), ctype="text/html; charset=utf-8")
                return
            if path == "/api/entries":
                filtered = has_filters(qs)
                limit = None if filtered else DEFAULT_LIMIT
                items = list_entries(conn, qs, limit=limit)
                total = count_entries(conn, qs)
                self._json(200, {"items": items, "total": total,
                                 "limited": (not filtered) and total > len(items),
                                 "filtered": filtered})
                return
            if path == "/api/stats":
                self._json(200, stats(conn))
                return
            if path == "/api/expiring":
                self._json(200, expiring_entries(conn))
                return
            if path.startswith("/api/history/"):
                self._json(200, get_history(conn, self._id(path)))
                return
            if path == "/api/export":
                fmt = (qs.get("format") or "json").lower()
                if fmt not in ("csv", "json", "xml"):
                    fmt = "json"
                rows = list_entries(conn, qs)
                body, ctype = export_bytes(rows, fmt)
                stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                self._send(200, body, ctype=ctype + "; charset=utf-8",
                           extra={"Content-Disposition": f'attachment; filename="savemymind-{stamp}.{fmt}"'})
                return
            if path.startswith("/api/suppression/"):
                entry = get_entry(conn, self._id(path))
                if not entry:
                    self._json(404, {"error": "entry not found"})
                    return
                if norm_stato(entry.get("stato")) not in SUPPRESSIBLE:
                    self._json(400, {"error": "status is not suppressible"})
                    return
                self._send(200, suppression_xml([entry]).encode("utf-8"), ctype="text/plain; charset=utf-8")
                return
            self._json(404, {"error": "not found"})

        def do_POST(self):
            path = urlparse(self.path).path
            if path == "/api/import":
                data = self._read_json()
                if data is None:
                    self._json(400, {"error": "invalid JSON"})
                    return
                # Commit path: the preview may send back entries with adjusted status.
                if isinstance(data.get("entries"), list):
                    imported = dupes = 0
                    for e in data["entries"]:
                        if not (e.get("cve") or "").strip():
                            continue
                        if find_duplicates(conn, e):
                            dupes += 1
                            continue
                        create_entry(conn, e)
                        imported += 1
                    self._json(200, {"imported": imported, "skipped_dupes": dupes, "skipped_no_id": 0})
                    return
                parsed = parse_import(data.get("xml") or "")
                if parsed is None:
                    self._json(400, {"error": "invalid or unreadable XML"})
                    return
                entries, skipped = parsed
                if not data.get("commit"):
                    self._json(200, {"count": len(entries), "skipped_no_id": skipped,
                                     "entries": entries[:100]})
                    return
                imported = dupes = 0
                for e in entries:
                    if find_duplicates(conn, e):
                        dupes += 1
                        continue
                    create_entry(conn, e)
                    imported += 1
                self._json(200, {"imported": imported, "skipped_dupes": dupes,
                                 "skipped_no_id": skipped})
                return
            if path != "/api/entries":
                self._json(404, {"error": "not found"})
                return
            data = self._read_json()
            if data is None:
                self._json(400, {"error": "invalid JSON"})
                return
            err = validate(data)
            if err:
                self._json(400, {"error": err})
                return
            if not data.get("force"):
                dups = find_duplicates(conn, data)
                if dups:
                    self._json(409, {"error": "duplicate", "existing": dups})
                    return
            self._json(201, {"id": create_entry(conn, data)})

        def do_PUT(self):
            parsed = urlparse(self.path)
            if not parsed.path.startswith("/api/entries/"):
                self._json(404, {"error": "not found"})
                return
            entry_id = self._id(parsed.path)
            data = self._read_json()
            if entry_id is None or data is None:
                self._json(400, {"error": "invalid request"})
                return
            err = validate(data)
            if err:
                self._json(400, {"error": err})
                return
            if update_entry(conn, entry_id, data):
                self._json(200, {"id": entry_id})
            else:
                self._json(404, {"error": "entry not found"})

        def do_DELETE(self):
            parsed = urlparse(self.path)
            entry_id = self._id(parsed.path)
            if not parsed.path.startswith("/api/entries/") or entry_id is None:
                self._json(400, {"error": "invalid request"})
                return
            if delete_entry(conn, entry_id):
                self._json(200, {"deleted": entry_id})
            else:
                self._json(404, {"error": "entry not found"})

    return Handler


def run(db_path, port, open_browser):
    fresh = not os.path.exists(db_path)
    conn = connect(db_path)
    print(("Created a new database: " if fresh else "Using existing database: ") + db_path)
    handler = make_handler(conn)
    httpd = None
    for candidate in range(port, port + 20):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", candidate), handler)
            port = candidate
            break
        except OSError:
            continue
    if httpd is None:
        print("error: no free port found.", file=sys.stderr)
        return 1
    url = f"http://127.0.0.1:{port}/"
    print(f"SaveMyMind is running at {url}")
    print("Your data is saved in the database file above. Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped. Your data is safe in the database file.")
    finally:
        httpd.server_close()
        conn.close()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Local knowledge base of vulnerability-triage decisions.")
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args(argv)
    return run(args.db, args.port, not args.no_browser)

# ---------------------------------------------------------------------------
# Embedded GUI (served at /). Offline: system fonts only, no external assets.
# ---------------------------------------------------------------------------

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SaveMyMind</title>
<style>
  :root{
    --bg:#0b0f16; --bg-2:#0e131c; --surface:#141b26; --surface-2:#1a2331; --raise:#202b3b;
    --line:#212c3b; --line-2:#2c3a4d; --ink:#eaf0f8; --ink-2:#c4d0de; --muted:#8492a5; --faint:#5a6878;
    --cyan:#4bcfe8; --cyan-2:#37bdd6; --cyan-dim:rgba(75,207,232,.12); --cyan-line:rgba(75,207,232,.42);
    --amber:#eab061; --amber-dim:rgba(234,176,97,.13); --amber-line:rgba(234,176,97,.45);
    --green:#5ccb9c; --green-line:rgba(92,203,156,.5); --green-dim:rgba(92,203,156,.13);
    --red:#f07a7c; --red-line:rgba(240,122,124,.5); --red-dim:rgba(240,122,124,.13);
    --grey:#aab6c6; --grey-line:rgba(170,182,198,.42); --grey-dim:rgba(170,182,198,.1);
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
    --cols:118px 138px minmax(0,1.25fr) minmax(0,1fr) 118px 168px;
    --sh:0 14px 40px rgba(0,0,0,.36);
  }
  *{box-sizing:border-box} html,body{margin:0}
  body{min-height:100vh; color:var(--ink); font-family:var(--sans); line-height:1.5; -webkit-font-smoothing:antialiased;
    background:radial-gradient(1100px 520px at 85% -12%, rgba(75,207,232,.09), transparent 60%),
      radial-gradient(760px 400px at 5% 0%, rgba(234,176,97,.05), transparent 55%),
      linear-gradient(180deg,var(--bg-2),var(--bg)); background-attachment:fixed}
  ::selection{background:var(--cyan-dim); color:#fff}
  ::-webkit-scrollbar{width:11px;height:11px}
  ::-webkit-scrollbar-thumb{background:#232f40;border-radius:9px;border:3px solid transparent;background-clip:content-box}
  input,select,textarea,button{font-family:inherit}

  header{position:sticky; top:0; z-index:30; background:rgba(11,15,22,.74); backdrop-filter:blur(14px) saturate(1.3); border-bottom:1px solid var(--line)}
  .top{max-width:1300px; margin:0 auto; padding:15px 24px; display:flex; align-items:center; gap:14px}
  .brand{display:flex; align-items:center; gap:11px}
  .brand .mk{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;background:linear-gradient(150deg,var(--cyan),var(--cyan-2)); box-shadow:0 6px 18px rgba(75,207,232,.3); color:#06202a}
  .brand .mk svg{width:18px;height:18px}
  .brand .wm{font-size:19px; font-weight:700; letter-spacing:-.02em}
  .brand .wm .a{color:var(--muted); font-weight:600} .brand .wm .b{color:var(--ink)}
  .spacer{flex:1}
  .btn{font-size:13.5px; font-weight:600; cursor:pointer; border:1px solid var(--line-2); background:var(--surface-2); color:var(--ink); padding:9px 15px; border-radius:9px; transition:transform .06s, background .18s, border-color .18s}
  .btn:hover{background:#20293a; border-color:#39485d} .btn:active{transform:translateY(1px)}
  .btn.primary{background:linear-gradient(150deg,var(--cyan),var(--cyan-2)); color:#06202a; border:none}
  .btn.ghost{background:transparent; border-color:transparent; color:var(--muted)} .btn.ghost:hover{background:#1a2434; color:var(--ink)}
  .btn.mini{padding:6px 10px; font-size:12px; border-radius:7px}
  .btn.danger{background:transparent; border-color:transparent; color:var(--red)} .btn.danger:hover{background:var(--red-dim)}
  .btn:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,.btn-new:focus-visible{outline:2px solid var(--cyan); outline-offset:2px}
  .exportwrap{position:relative}
  .menu{position:absolute; right:0; top:calc(100% + 6px); background:var(--surface); border:1px solid var(--line-2); border-radius:10px; box-shadow:var(--sh); padding:6px; display:none; z-index:40; min-width:150px}
  .menu.open{display:block}
  .menu button{display:block; width:100%; text-align:left; background:transparent; border:none; color:var(--ink); font-size:13px; padding:9px 11px; border-radius:7px; cursor:pointer}
  .menu button:hover{background:var(--surface-2)} .menu .hd{font-size:10px; color:var(--faint); padding:5px 11px 3px; text-transform:uppercase; letter-spacing:.1em}

  .wrap{max-width:1300px; margin:0 auto; padding:24px; display:grid; grid-template-columns:296px minmax(0,1fr); gap:24px; align-items:start}
  @media (max-width:980px){ .wrap{grid-template-columns:1fr} }

  /* sidebar */
  .side{position:sticky; top:86px; display:flex; flex-direction:column; gap:16px}
  @media (max-width:980px){ .side{position:static} }
  .card{background:var(--surface); border:1px solid var(--line); border-radius:14px; box-shadow:var(--sh)}
  .side .hd{display:flex; align-items:center; gap:8px; padding:15px 16px 0}
  .side .hd h3{margin:0; font-size:14px; font-weight:700}
  .side .hd .pill{margin-left:auto; font-size:11px; font-family:var(--mono); color:#06202a; background:var(--amber); padding:2px 8px; border-radius:999px; font-weight:700}
  .side .hd .pill.zero{background:var(--surface-2); color:var(--faint)}
  .exp-list{padding:12px 12px 14px; display:flex; flex-direction:column; gap:8px; max-height:60vh; overflow:auto}
  .exp-item{padding:10px 12px; border:1px solid var(--line); border-radius:10px; cursor:pointer; transition:border-color .15s, background .15s}
  .exp-item:hover{border-color:var(--cyan-line); background:#101825}
  .exp-item .l1{display:flex; align-items:center; gap:8px; margin-bottom:3px}
  .exp-item .cveid{font-family:var(--mono); font-size:12px; color:#f0cd95; overflow:hidden; text-overflow:ellipsis; white-space:nowrap}
  .exp-item .pk{font-family:var(--mono); font-size:11px; color:var(--muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap}
  .exp-item .when{font-size:11px; font-weight:600}
  .exp-item .when.over{color:var(--red)} .exp-item .when.soon{color:var(--amber)}
  .side .empty-s{padding:22px 16px; text-align:center; color:var(--faint); font-size:13px}

  /* hero */
  .hero{margin:2px 0 20px; display:flex; gap:14px; align-items:center}
  .hero .searchwrap{position:relative; flex:1}
  .hero .searchwrap .ic{position:absolute; left:15px; top:50%; transform:translateY(-50%); color:var(--muted); display:flex}
  .hero .searchwrap .ic svg{width:18px;height:18px}
  .hero input{width:100%; font-size:14.5px; color:var(--ink); background:var(--surface); border:1px solid var(--line-2); border-radius:12px; padding:13px 15px 13px 44px; transition:border-color .18s, box-shadow .18s, background .18s}
  .hero input:focus{outline:none; border-color:var(--cyan-line); box-shadow:0 0 0 4px var(--cyan-dim); background:#101724}
  .btn-new{display:inline-flex; align-items:center; gap:9px; font-size:14.5px; font-weight:650; cursor:pointer; color:#06202a; background:linear-gradient(150deg,var(--cyan),var(--cyan-2)); border:none; border-radius:12px; padding:13px 22px; box-shadow:0 10px 26px rgba(75,207,232,.28); transition:transform .08s, box-shadow .2s, filter .2s; white-space:nowrap}
  .btn-new:hover{filter:brightness(1.05); box-shadow:0 14px 32px rgba(75,207,232,.4); transform:translateY(-1px)}
  .btn-new svg{width:18px;height:18px}

  .stats{display:flex; flex-wrap:wrap; gap:11px; margin-bottom:18px}
  .stat{flex:1; min-width:104px; display:flex; align-items:center; gap:11px; background:var(--surface); border:1px solid var(--line); border-radius:12px; padding:12px 14px}
  .stat .num{font-size:20px; font-weight:750; line-height:1} .stat .cap{font-size:11.5px; color:var(--muted)}
  .stat .d{width:9px;height:9px;border-radius:50%; flex:none}
  .stat.tot{border-color:var(--cyan-line)} .stat.tot .num{color:var(--cyan)}
  .stat.warn{border-color:var(--amber-line)} .stat.warn .num{color:var(--amber)}
  .stat.bad{border-color:var(--red-line)} .stat.bad .num{color:var(--red)}

  .filters{background:var(--surface); border:1px solid var(--line); border-radius:14px; padding:16px 18px; margin-bottom:18px}
  .filters .row{display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px}
  .filters .grp{display:flex; flex-direction:column; gap:6px}
  .filters label{font-size:11.5px; color:var(--muted)}
  .filters input, .filters select{font-size:13px; color:var(--ink); background:var(--surface-2); border:1px solid var(--line-2); border-radius:9px; padding:9px 11px; transition:border-color .18s, box-shadow .18s}
  .filters input{font-family:var(--mono)}
  .filters input:focus, .filters select:focus{outline:none; border-color:var(--cyan-line); box-shadow:0 0 0 3px var(--cyan-dim)}
  .filters .bar{display:flex; gap:10px; margin-top:14px; justify-content:flex-end}

  .board{background:var(--surface); border:1px solid var(--line); border-radius:16px; overflow:hidden; box-shadow:var(--sh)}
  .thead{display:grid; grid-template-columns:var(--cols); gap:12px; padding:13px 20px; border-bottom:1px solid var(--line); background:#111825}
  .thead span{font-size:11px; color:var(--faint); font-weight:600} .thead .a{text-align:right}
  @media (max-width:900px){ .thead{display:none} }
  .rec{padding:14px 20px; border-bottom:1px solid var(--line); animation:in .3s ease both; animation-delay:calc(var(--i,0)*26ms)}
  .rec:last-child{border-bottom:none} .rec:hover{background:#101825}
  @keyframes in{from{opacity:0; transform:translateY(6px)} to{opacity:1; transform:translateY(0)}}
  .rmain{display:grid; grid-template-columns:var(--cols); gap:12px; align-items:center}
  .badge{display:inline-flex; align-items:center; gap:7px; font-size:11px; font-weight:650; padding:5px 10px; border-radius:8px; border:1px solid; white-space:nowrap; justify-self:start}
  .badge .d{width:8px;height:8px;border-radius:50%}
  .badge.falso_positivo{color:#a6e7cd; background:var(--green-dim); border-color:var(--green-line)} .badge.falso_positivo .d{background:var(--green)}
  .badge.non_falso_positivo{color:#f7b0b1; background:var(--red-dim); border-color:var(--red-line)} .badge.non_falso_positivo .d{background:var(--red)}
  .badge.deroga{color:#d3dbe6; background:var(--grey-dim); border-color:var(--grey-line)} .badge.deroga .d{background:var(--grey)}
  .idcell{display:flex; align-items:center; gap:6px; min-width:0}
  .idcell .txt{overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:var(--mono)}
  .idcell.cve .txt{font-size:12.5px; color:#f0cd95; background:var(--amber-dim); border:1px solid var(--amber-line); padding:3px 8px; border-radius:6px}
  .idcell.pkg .txt{font-size:12.5px; color:var(--ink)} .idcell.cpe .txt{font-size:12px; color:var(--muted)}
  .cpy{flex:none; opacity:0; background:transparent; border:none; color:var(--muted); cursor:pointer; padding:3px; border-radius:5px; display:flex; transition:opacity .15s, color .15s, background .15s}
  .cpy svg{width:14px;height:14px} .rec:hover .cpy{opacity:.75} .cpy:hover{color:var(--cyan); background:var(--surface-2); opacity:1}
  .t-date{font-size:11.5px; color:var(--faint); white-space:nowrap}
  .exp{display:inline-block; margin-top:3px; font-size:10.5px; font-weight:650; padding:2px 7px; border-radius:5px; white-space:nowrap}
  .exp.over{color:#fff; background:var(--red)} .exp.soon{color:#06202a; background:var(--amber)} .exp.ok{color:var(--faint); background:var(--surface-2)}
  .acts{display:flex; gap:3px; justify-content:flex-end; flex-wrap:wrap}
  .rdesc{grid-column:1/-1; margin:10px 0 0; color:var(--ink-2); font-size:14px; white-space:pre-wrap; word-break:break-word; line-height:1.55}
  .rdesc.empty{color:var(--faint); font-style:italic}
  .rmeta{grid-column:1/-1; margin:8px 0 0; display:flex; flex-wrap:wrap; gap:15px; font-size:11.5px; color:var(--faint)}
  .rmeta b{color:#556577; font-weight:600; margin-right:5px; font-size:11px} .rmeta .mono{font-family:var(--mono)}
  @media (max-width:900px){ .rmain{grid-template-columns:1fr auto; gap:8px} .rmain .t-cpe,.rmain .t-datecol{display:none} }
  .empty{padding:64px 24px; text-align:center}
  .empty .ill{width:56px;height:56px;margin:0 auto 16px;border-radius:16px;display:grid;place-items:center;background:var(--surface-2); border:1px solid var(--line-2); color:var(--cyan)} .empty .ill svg{width:26px;height:26px}
  .empty h3{margin:0 0 6px; font-size:17px} .empty p{margin:0 0 18px; font-size:14px; color:var(--muted)}
  .foot{padding:11px 20px; font-size:11.5px; color:var(--faint); border-top:1px solid var(--line); background:#0f1521}

  #overlay{position:fixed; inset:0; background:rgba(6,9,14,.62); backdrop-filter:blur(2px); opacity:0; pointer-events:none; transition:opacity .25s; z-index:40}
  #overlay.open{opacity:1; pointer-events:auto}
  #drawer{position:fixed; top:0; right:0; height:100vh; width:min(470px,94vw); z-index:50; background:linear-gradient(180deg,#141c29,#101622); border-left:1px solid var(--line-2); box-shadow:-26px 0 60px rgba(0,0,0,.5); transform:translateX(103%); transition:transform .3s cubic-bezier(.22,.8,.2,1); display:flex; flex-direction:column}
  #drawer.open{transform:translateX(0)}
  .dhead{display:flex; align-items:center; gap:11px; padding:20px 24px; border-bottom:1px solid var(--line)}
  .dhead h2{margin:0; font-size:16px; font-weight:700}
  .dclose{margin-left:auto; background:transparent; border:none; color:var(--muted); font-size:22px; cursor:pointer; padding:2px 8px; border-radius:8px; line-height:1} .dclose:hover{background:#1b2534; color:var(--ink)}
  .dbody{padding:22px 24px; overflow-y:auto; flex:1}
  .dfoot{padding:16px 24px; border-top:1px solid var(--line); display:flex; gap:10px} .dfoot .primary{flex:1}
  .field{margin-bottom:15px}
  .field label{display:flex; align-items:center; gap:7px; margin-bottom:6px; font-size:12px; color:var(--muted)}
  .field label .req{width:5px;height:5px;border-radius:50%;background:var(--cyan)} .field label .hint{margin-left:auto; font-size:10.5px; color:var(--faint)}
  .field input,.field textarea,.field select{width:100%; font-size:13px; color:var(--ink); background:var(--surface-2); border:1px solid var(--line-2); border-radius:9px; padding:11px 12px; transition:border-color .18s, box-shadow .18s, background .18s}
  .field input,.field textarea{font-family:var(--mono)}
  .field textarea{font-family:var(--sans); min-height:88px; resize:vertical; line-height:1.55}
  .field select{cursor:pointer}
  .field input:focus,.field textarea:focus,.field select:focus{outline:none; border-color:var(--cyan-line); box-shadow:0 0 0 3px var(--cyan-dim); background:#151c29}
  .g2{display:grid; grid-template-columns:1fr 1fr; gap:12px}
  #expiry-field{display:none} body.can-expire #expiry-field{display:block}
  .hist{margin-top:8px; border-top:1px solid var(--line); padding-top:16px}
  .hist h4{margin:0 0 10px; font-size:12px; color:var(--muted); font-weight:600}
  .hist .h{display:flex; gap:10px; font-size:12px; padding:7px 0; border-bottom:1px solid var(--line)}
  .hist .h:last-child{border-bottom:none}
  .hist .h .t{font-family:var(--mono); color:var(--faint); font-size:11px; white-space:nowrap}
  .hist .h .c b{color:var(--ink-2)} .hist .h .c .ar{color:var(--cyan); margin:0 4px}
  .hist .none{font-size:12px; color:var(--faint)}

  /* duplicate modal */
  #dupmodal{position:fixed; inset:0; z-index:60; display:none; align-items:center; justify-content:center; padding:20px; background:rgba(6,9,14,.66); backdrop-filter:blur(3px)}
  #dupmodal.open{display:flex}
  #importmodal{position:fixed; inset:0; z-index:60; display:none; align-items:center; justify-content:center; padding:20px; background:rgba(6,9,14,.66); backdrop-filter:blur(3px)}
  #importmodal.open{display:flex}
  .ir{display:flex; align-items:center; gap:10px; padding:6px 0; border-bottom:1px solid var(--line)}
  .ir:last-child{border-bottom:none}
  .ir .istato{flex:none; font-size:12px; color:var(--ink); background:var(--surface-2); border:1px solid var(--line-2); border-radius:7px; padding:5px 7px; cursor:pointer}
  .ir .istato:focus{outline:none; border-color:var(--cyan-line); box-shadow:0 0 0 2px var(--cyan-dim)}
  .ir .iv{font-family:var(--mono); font-size:12px; color:var(--ink-2); overflow:hidden; text-overflow:ellipsis; white-space:nowrap}
  .dup{width:min(520px,96vw); background:var(--surface); border:1px solid var(--line-2); border-radius:16px; box-shadow:var(--sh); overflow:hidden}
  .dup .dh{padding:18px 22px; border-bottom:1px solid var(--line); display:flex; align-items:center; gap:10px}
  .dup .dh .ic{color:var(--amber); display:flex} .dup .dh h3{margin:0; font-size:16px}
  .dup .db{padding:18px 22px; font-size:14px; color:var(--ink-2)}
  .dup .ex{margin-top:12px; border:1px solid var(--line); border-radius:10px; padding:12px 14px; font-size:13px}
  .dup .ex .r{display:flex; gap:8px; margin-bottom:5px} .dup .ex b{color:var(--faint); font-size:11px; width:66px; flex:none} .dup .ex .v{font-family:var(--mono); color:var(--ink); overflow:hidden; text-overflow:ellipsis}
  .dup .df{padding:16px 22px; border-top:1px solid var(--line); display:flex; gap:10px; justify-content:flex-end}

  #toast{position:fixed; left:50%; bottom:30px; transform:translateX(-50%) translateY(18px); background:#121a27; color:var(--ink); border:1px solid var(--line-2); padding:12px 18px; border-radius:11px; font-size:13.5px; opacity:0; pointer-events:none; transition:.26s cubic-bezier(.2,.8,.2,1); z-index:80; box-shadow:0 12px 34px rgba(0,0,0,.5); display:flex; align-items:center; gap:9px}
  #toast::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--green)}
  #toast.show{opacity:1; transform:translateX(-50%) translateY(0)} #toast.err{border-color:var(--red-line)} #toast.err::before{background:var(--red)}
  @media (prefers-reduced-motion:reduce){ *{animation:none!important; transition:none!important} }
</style>
</head>
<body>
<header>
  <div class="top">
    <div class="brand">
      <div class="mk"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3h12a1 1 0 0 1 1 1v17l-7-4-7 4V4a1 1 0 0 1 1-1z"/></svg></div>
      <div class="wm"><span class="a">Save</span><span class="b">MyMind</span></div>
    </div>
    <div class="spacer"></div>
    <button class="btn" id="import-btn" title="Import a suppression.xml file">Import</button>
    <input type="file" id="import-file" accept=".xml,text/xml" style="display:none">
    <div class="exportwrap">
      <button class="btn" id="export-btn">Export ▾</button>
      <div class="menu" id="export-menu">
        <div class="hd">Export current view</div>
        <button data-fmt="csv">CSV</button>
        <button data-fmt="xlsx-json">JSON</button>
        <button data-fmt="xml">XML</button>
      </div>
    </div>
  </div>
</header>

<div class="wrap">
  <!-- sidebar -->
  <aside class="side">
    <div class="card">
      <div class="hd"><h3>Expiring &amp; overdue</h3><span class="pill zero" id="exp-count">0</span></div>
      <div class="exp-list" id="exp-list"><div class="empty-s">Nothing expiring.</div></div>
    </div>
  </aside>

  <!-- main -->
  <main>
    <div class="hero">
      <div class="searchwrap">
        <span class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg></span>
        <input id="q" placeholder="Search everything as you type…">
      </div>
      <button class="btn-new" id="new-btn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>New entry</button>
    </div>

    <div class="stats" id="stats"></div>

    <div class="filters">
      <div class="row">
        <div class="grp"><label for="s-package">Package</label><input id="s-package" placeholder="search…"></div>
        <div class="grp"><label for="s-cve">CVE / GHSA</label><input id="s-cve" placeholder="search…"></div>
        <div class="grp"><label for="s-cpe">CPE</label><input id="s-cpe" placeholder="search…"></div>
        <div class="grp"><label for="s-sha1">SHA1</label><input id="s-sha1" placeholder="search…"></div>
        <div class="grp"><label for="s-file">File path</label><input id="s-file" placeholder="search…"></div>
        <div class="grp"><label for="s-author">Author</label><input id="s-author" placeholder="search…"></div>
        <div class="grp"><label for="s-stato">Status</label>
          <select id="s-stato"><option value="">All</option><option value="falso_positivo">False positive</option><option value="non_falso_positivo">Not a false positive</option><option value="deroga">Waiver</option></select>
        </div>
        <div class="grp"><label for="s-expiry">Expiry</label>
          <select id="s-expiry"><option value="">Any</option><option value="soon">Expiring soon</option><option value="expired">Expired</option><option value="active">Still valid</option></select>
        </div>
        <div class="grp"><label for="s-from">Created from</label><input id="s-from" type="date" min="2000-01-01" max="2900-12-31"></div>
        <div class="grp"><label for="s-to">Created to</label><input id="s-to" type="date" min="2000-01-01" max="2900-12-31"></div>
      </div>
      <div class="bar"><button class="btn primary" id="search-btn">Search</button><button class="btn ghost" id="reset-btn">Reset</button></div>
    </div>

    <div class="board">
      <div class="thead"><span>Status</span><span>CVE / GHSA</span><span>Package</span><span>CPE</span><span>Date</span><span class="a">Actions</span></div>
      <div id="results"></div>
      <div class="foot" id="foot"></div>
    </div>
  </main>
</div>

<div id="overlay"></div>
<aside id="drawer" aria-hidden="true">
  <div class="dhead"><h2 id="form-title">New entry</h2><button class="dclose" id="dclose" title="Close">&times;</button></div>
  <form id="entry-form" autocomplete="off" style="display:contents">
    <div class="dbody">
      <div class="field"><label for="f-stato">Status</label>
        <select id="f-stato"><option value="falso_positivo">🟢 False positive</option><option value="non_falso_positivo">🔴 Not a false positive</option><option value="deroga">⚪ Waiver (accepted risk)</option></select>
      </div>
      <div class="field" id="expiry-field"><label for="f-expires">Expiry date <span class="hint">used as until in the XML</span></label><input id="f-expires" type="date" min="2000-01-01" max="2900-12-31"></div>
      <div class="field"><label for="f-package">Package</label><input id="f-package" placeholder="pkg:npm/lodash@4.17.15"></div>
      <div class="g2">
        <div class="field"><label for="f-cve">CVE / GHSA <span class="req"></span></label><input id="f-cve" placeholder="CVE-2020-8203 / GHSA-…" required></div>
        <div class="field"><label for="f-cpe">CPE</label><input id="f-cpe" placeholder="optional"></div>
      </div>
      <div class="g2">
        <div class="field"><label for="f-sha1">SHA1</label><input id="f-sha1" placeholder="optional"></div>
        <div class="field"><label for="f-file">File path</label><input id="f-file" placeholder="optional"></div>
      </div>
      <div class="field"><label for="f-author">Author</label><input id="f-author" placeholder="optional"></div>
      <div class="field"><label for="f-desc">Description / reason</label><textarea id="f-desc" placeholder="Why it's a false positive, why it must NOT be suppressed, waiver conditions…"></textarea></div>
      <div class="hist" id="hist-box" style="display:none"><h4>Change history</h4><div id="hist-list"></div></div>
    </div>
    <div class="dfoot"><button type="submit" class="btn primary" id="save-btn">Save entry</button><button type="button" class="btn ghost" id="cancel-edit">Cancel</button></div>
  </form>
</aside>

<div id="dupmodal">
  <div class="dup">
    <div class="dh"><span class="ic"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg></span><h3>Possible duplicate</h3></div>
    <div class="db">An entry with this CVE and package already exists:<div class="ex" id="dup-ex"></div></div>
    <div class="df"><button class="btn ghost" id="dup-cancel">Cancel</button><button class="btn primary" id="dup-force">Insert anyway</button></div>
  </div>
</div>

<div id="importmodal">
  <div class="dup" style="width:min(560px,96vw)">
    <div class="dh"><span class="ic"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M8 11l4 4 4-4"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></svg></span><h3>Import suppression file</h3></div>
    <div class="db"><div id="import-summary">Choose a suppression .xml file.</div><div class="ex" id="import-preview" style="max-height:240px; overflow:auto; display:none; margin-top:12px"></div></div>
    <div class="df"><button class="btn ghost" id="import-cancel">Cancel</button><button class="btn primary" id="import-confirm" disabled>Import</button></div>
  </div>
</div>

<div id="toast"></div>

<script>
const $=s=>document.querySelector(s);
const api="/api/entries";
let editingId=null; let pendingData=null;
const STATI={falso_positivo:{short:"FALSE POS"},non_falso_positivo:{short:"NOT FP"},deroga:{short:"WAIVER"}};
const LABEL={falso_positivo:"False positive",non_falso_positivo:"Not a false positive",deroga:"Waiver",expires_at:"Expiry",created:"Created"};
const SUPPRESSIBLE=new Set(["falso_positivo","deroga"]);
const COPY_SVG='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';

function toast(m,e=false){const t=$("#toast");t.textContent=m;t.className="show"+(e?" err":"");clearTimeout(t._t);t._t=setTimeout(()=>t.className="",2600);}
function esc(s){return (s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
async function clip(text){try{await navigator.clipboard.writeText(text);}catch{const ta=document.createElement("textarea");ta.value=text;document.body.appendChild(ta);ta.select();document.execCommand("copy");ta.remove();}}
function daysTo(d){const t=new Date();t.setHours(0,0,0,0);const x=new Date(d+"T00:00:00");return Math.round((x-t)/86400000);}

function updateExpiryVisibility(){ document.body.classList.toggle("can-expire", SUPPRESSIBLE.has($("#f-stato").value)); }

async function openDrawer(en){
  $("#hist-box").style.display="none"; $("#hist-list").innerHTML="";
  if(en){
    $("#f-stato").value=en.stato||"falso_positivo"; $("#f-expires").value=en.expires_at||"";
    $("#f-package").value=en.package||"";$("#f-cve").value=en.cve||"";$("#f-cpe").value=en.cpe||"";
    $("#f-sha1").value=en.sha1||"";$("#f-file").value=en.file_path||"";$("#f-author").value=en.author||"";$("#f-desc").value=en.description||"";
    editingId=en.id; $("#form-title").textContent="Edit #"+en.id; $("#save-btn").textContent="Update";
    loadHistory(en.id);
  } else {
    $("#entry-form").reset(); $("#f-stato").value="falso_positivo"; $("#f-expires").value=""; editingId=null;
    $("#form-title").textContent="New entry"; $("#save-btn").textContent="Save entry";
  }
  updateExpiryVisibility();
  $("#drawer").classList.add("open"); $("#overlay").classList.add("open"); $("#drawer").setAttribute("aria-hidden","false");
  setTimeout(()=>$("#f-package").focus(),120);
}
function closeDrawer(){ $("#drawer").classList.remove("open"); $("#overlay").classList.remove("open"); $("#drawer").setAttribute("aria-hidden","true"); }

async function loadHistory(id){
  const h=await (await fetch("/api/history/"+id)).json();
  if(!h.length){ $("#hist-box").style.display="block"; $("#hist-list").innerHTML='<div class="none">No changes recorded yet.</div>'; return; }
  $("#hist-box").style.display="block";
  $("#hist-list").innerHTML=h.map(x=>{
    const when=(x.changed_at||"").replace("T"," ");
    const fl=LABEL[x.field]||x.field;
    let c;
    if(x.field==="created") c=`Created as <b>${esc(LABEL[x.new_value]||x.new_value||"")}</b>`;
    else if(x.field==="stato") c=`Status <b>${esc(LABEL[x.old_value]||x.old_value||"—")}</b><span class="ar">→</span><b>${esc(LABEL[x.new_value]||x.new_value||"—")}</b>`;
    else c=`${esc(fl)} <b>${esc(x.old_value||"—")}</b><span class="ar">→</span><b>${esc(x.new_value||"—")}</b>`;
    return `<div class="h"><span class="t">${esc(when)}</span><span class="c">${c}</span></div>`;
  }).join("");
}

function formData(){return {stato:$("#f-stato").value,expires_at:$("#f-expires").value,package:$("#f-package").value,cve:$("#f-cve").value,cpe:$("#f-cpe").value,sha1:$("#f-sha1").value,file_path:$("#f-file").value,author:$("#f-author").value,description:$("#f-desc").value};}

async function save(ev){
  ev.preventDefault(); const d=formData();
  if(!d.cve.trim()){ toast("CVE/GHSA is required",true); return; }
  const url=editingId?`${api}/${editingId}`:api;
  const r=await fetch(url,{method:editingId?"PUT":"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)});
  if(r.status===409){ const j=await r.json(); pendingData=d; showDup(j.existing); return; }
  if(r.ok){ toast(editingId?"Entry updated":"Entry saved"); closeDrawer(); load(); }
  else { const j=await r.json().catch(()=>({})); toast(j.error||"Error",true); }
}
function showDup(existing){
  const e=existing[0]||{};
  $("#dup-ex").innerHTML=`
    <div class="r"><b>Status</b><span class="v">${esc((STATI[e.stato]||{}).short||e.stato||"")}</span></div>
    <div class="r"><b>CVE</b><span class="v">${esc(e.cve||"")}</span></div>
    <div class="r"><b>Package</b><span class="v">${esc(e.package||"")}</span></div>
    <div class="r"><b>Reason</b><span class="v">${esc(e.description||"—")}</span></div>`;
  $("#dupmodal").classList.add("open");
}
async function forceInsert(){
  $("#dupmodal").classList.remove("open");
  const r=await fetch(api,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({...pendingData,force:true})});
  if(r.ok){ toast("Entry saved"); closeDrawer(); load(); } else toast("Error",true);
}
async function remove(id){
  if(!confirm("Delete this entry? This cannot be undone.")) return;
  const r=await fetch(`${api}/${id}`,{method:"DELETE"});
  if(r.ok){ toast("Entry deleted"); if(editingId===id) closeDrawer(); load(); } else toast("Error",true);
}
async function copyXml(id){
  const r=await fetch(`/api/suppression/${id}`);
  if(!r.ok){ toast("XML not available for this status",true); return; }
  await clip(await r.text()); toast("suppression.xml copied to clipboard");
}
function meta(l,v,mono){return v?`<span><b>${l}</b><span class="${mono?"mono":""}">${esc(v)}</span></span>`:"";}
function expTag(e){
  if(!e.expires_at||!SUPPRESSIBLE.has(e.stato)) return "";
  const dd=daysTo(e.expires_at);
  if(dd<0) return `<span class="exp over">expired ${-dd}d ago</span>`;
  if(dd<=30) return `<span class="exp soon">${dd}d left</span>`;
  return `<span class="exp ok">until ${esc(e.expires_at)}</span>`;
}
function idcell(kind,label,v){
  return `<span class="idcell ${kind}"><span class="txt" title="${esc(v)}">${esc(v)}</span><button class="cpy" data-copy="${esc(v)}" title="Copy ${label}">${COPY_SVG}</button></span>`;
}

async function loadStats(){
  const s=await (await fetch("/api/stats")).json(); const b=s.by_stato||{};
  const tc=(s.top_cve&&s.top_cve[0])?`${esc(s.top_cve[0][0])} · ${s.top_cve[0][1]}`:"—";
  const tp=(s.top_package&&s.top_package[0])?`${esc(s.top_package[0][0])} · ${s.top_package[0][1]}`:"—";
  $("#stats").innerHTML=`
    <div class="stat tot"><div><div class="num">${s.total||0}</div><div class="cap">Total</div></div></div>
    <div class="stat"><span class="d" style="background:var(--green)"></span><div><div class="num">${b.falso_positivo||0}</div><div class="cap">False positive</div></div></div>
    <div class="stat"><span class="d" style="background:var(--red)"></span><div><div class="num">${b.non_falso_positivo||0}</div><div class="cap">Not a FP</div></div></div>
    <div class="stat"><span class="d" style="background:var(--grey)"></span><div><div class="num">${b.deroga||0}</div><div class="cap">Waivers</div></div></div>
    <div class="stat warn"><div><div class="num">${s.expiring||0}</div><div class="cap">Expiring soon</div></div></div>
    <div class="stat bad"><div><div class="num">${s.expired||0}</div><div class="cap">Expired</div></div></div>`;
}

async function loadExpiring(){
  const rows=await (await fetch("/api/expiring")).json();
  $("#exp-count").textContent=rows.length;
  $("#exp-count").className="pill"+(rows.length?"":" zero");
  const box=$("#exp-list");
  if(!rows.length){ box.innerHTML='<div class="empty-s">Nothing expiring.</div>'; return; }
  box.innerHTML=rows.map(e=>{
    const dd=daysTo(e.expires_at);
    const w=dd<0?`<span class="when over">${-dd}d overdue</span>`:`<span class="when soon">${dd}d left</span>`;
    return `<div class="exp-item" data-open='${esc(JSON.stringify(e))}'>
      <div class="l1"><span class="cveid">${esc(e.cve)}</span>${w}</div>
      <div class="pk">${esc(e.package)}</div></div>`;
  }).join("");
  box.querySelectorAll("[data-open]").forEach(el=>el.onclick=()=>{ try{openDrawer(JSON.parse(el.dataset.open));}catch{} });
}

function render(items){
  const box=$("#results");
  if(!items.length){
    box.innerHTML=`<div class="empty"><div class="ill"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3h12a1 1 0 0 1 1 1v17l-7-4-7 4V4a1 1 0 0 1 1-1z"/></svg></div><h3>Nothing here yet</h3><p>Save your first triage decision, or widen the search.</p><button class="btn primary" onclick="openDrawer(null)">New entry</button></div>`;
    $("#foot").textContent=""; return;
  }
  box.innerHTML=items.map((e,i)=>{
    const st=STATI[e.stato]||STATI.falso_positivo;
    const copy=SUPPRESSIBLE.has(e.stato)?`<button class="btn mini" data-xml="${e.id}" title="Copy suppression.xml to clipboard">Copy XML</button>`:"";
    return `<div class="rec" style="--i:${i}">
      <div class="rmain">
        <span class="badge ${e.stato||"falso_positivo"}"><span class="d"></span>${st.short}</span>
        ${idcell("cve","CVE",e.cve)}
        ${e.package?idcell("pkg","package",e.package):'<span class="t-pkg" style="color:var(--faint)">—</span>'}
        <span class="t-cpe">${e.cpe?idcell("cpe","CPE",e.cpe):'<span style="color:var(--faint)">—</span>'}</span>
        <span class="t-datecol"><span class="t-date">${esc((e.created_at||"").slice(0,10))}</span>${expTag(e)?"<br>"+expTag(e):""}</span>
        <span class="acts">${copy}<button class="btn mini" data-edit="${e.id}">Edit</button><button class="btn mini danger" data-del="${e.id}">Delete</button></span>
      </div>
      <div class="rdesc ${e.description?"":"empty"}">${e.description?esc(e.description):"No description"}</div>
      <div class="rmeta">${meta("SHA1",e.sha1,1)}${meta("PATH",e.file_path,1)}${meta("AUTHOR",e.author,0)}${meta("CREATED",(e.created_at||"").replace("T"," "),1)}${e.updated_at&&e.updated_at!==e.created_at?meta("UPDATED",(e.updated_at||"").replace("T"," "),1):""}</div>
    </div>`;
  }).join("");
  box.querySelectorAll("[data-copy]").forEach(b=>b.onclick=async()=>{await clip(b.dataset.copy); toast("Copied");});
  box.querySelectorAll("[data-xml]").forEach(b=>b.onclick=()=>copyXml(+b.dataset.xml));
  box.querySelectorAll("[data-edit]").forEach(b=>b.onclick=()=>{const e=items.find(x=>x.id==b.dataset.edit);if(e)openDrawer(e);});
  box.querySelectorAll("[data-del]").forEach(b=>b.onclick=()=>remove(+b.dataset.del));
}

function filterParams(){
  const p=new URLSearchParams();
  const q=$("#q").value.trim(); if(q) p.set("q",q);
  const map={package:"s-package",cve:"s-cve",cpe:"s-cpe",sha1:"s-sha1",file_path:"s-file",author:"s-author",stato:"s-stato",expiry:"s-expiry",date_from:"s-from",date_to:"s-to"};
  for(const [k,id] of Object.entries(map)){const v=$("#"+id).value.trim();if(v) p.set(k,v);}
  return p;
}
async function load(){
  const p=filterParams();
  const data=await (await fetch(api+(p.toString()?"?"+p:""))).json();
  const items=data.items||[]; render(items); loadStats(); loadExpiring();
  let foot="";
  if(items.length){
    if(data.filtered) foot=`${data.total} ${data.total===1?"match":"matches"} · showing all`;
    else if(data.limited) foot=`showing latest ${items.length} of ${data.total}`;
    else foot=`${data.total} ${data.total===1?"entry":"entries"} · newest first`;
  }
  $("#foot").textContent=foot;
}

$("#entry-form").addEventListener("submit",save);
$("#f-stato").addEventListener("change",updateExpiryVisibility);
$("#new-btn").onclick=()=>openDrawer(null);
$("#dclose").onclick=closeDrawer; $("#cancel-edit").onclick=closeDrawer; $("#overlay").onclick=closeDrawer;
document.addEventListener("keydown",e=>{ if(e.key==="Escape"){ closeDrawer(); $("#dupmodal").classList.remove("open"); $("#importmodal").classList.remove("open"); $("#export-menu").classList.remove("open"); } });
$("#q").addEventListener("input",()=>{ clearTimeout(window._d); window._d=setTimeout(load,280); });
$("#q").addEventListener("keydown",e=>{ if(e.key==="Enter") load(); });
$("#search-btn").onclick=load;
["s-package","s-cve","s-cpe","s-sha1","s-file","s-author"].forEach(id=>$("#"+id).addEventListener("keydown",e=>{if(e.key==="Enter")load();}));
["s-stato","s-expiry","s-from","s-to"].forEach(id=>$("#"+id).addEventListener("change",load));
$("#reset-btn").onclick=()=>{ ["q","s-package","s-cve","s-cpe","s-sha1","s-file","s-author","s-from","s-to"].forEach(id=>$("#"+id).value=""); $("#s-stato").value=""; $("#s-expiry").value=""; load(); };
$("#dup-cancel").onclick=()=>$("#dupmodal").classList.remove("open");
$("#dup-force").onclick=forceInsert;

$("#import-btn").onclick=()=>$("#import-file").click();
$("#import-file").onchange=async(ev)=>{
  const f=ev.target.files[0]; ev.target.value=""; if(!f) return;
  const xml=await f.text(); window._importXml=xml;
  const r=await fetch("/api/import",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({xml,commit:false})});
  const j=await r.json();
  if(!r.ok){ toast(j.error||"Invalid file",true); return; }
  window._importEntries=j.entries||[];
  const s=`Found <b>${j.count}</b> entr${j.count===1?"y":"ies"} to import`+(j.skipped_no_id?` · ${j.skipped_no_id} block(s) skipped (no CVE/GHSA)`:"")+`. Adjust any status below if needed.`;
  $("#import-summary").innerHTML=s;
  const pv=$("#import-preview");
  if(window._importEntries.length){ pv.style.display="block";
    pv.innerHTML=window._importEntries.map((e,i)=>`<div class="ir">
      <select class="istato" data-i="${i}">
        <option value="falso_positivo"${e.stato==="falso_positivo"?" selected":""}>🟢 FP</option>
        <option value="non_falso_positivo"${e.stato==="non_falso_positivo"?" selected":""}>🔴 Not FP</option>
        <option value="deroga"${e.stato==="deroga"?" selected":""}>⚪ Waiver</option>
      </select>
      <span class="iv" title="${esc(e.cve)} · ${esc(e.package||"—")}">${esc(e.cve)} · ${esc(e.package||"—")}${e.expires_at?" · until "+esc(e.expires_at):""}</span>
    </div>`).join("");
    pv.querySelectorAll(".istato").forEach(sel=>sel.onchange=()=>{ window._importEntries[+sel.dataset.i].stato=sel.value; });
  } else pv.style.display="none";
  $("#import-confirm").disabled=!j.count; $("#import-confirm").textContent=j.count?`Import ${j.count}`:"Nothing to import";
  $("#importmodal").classList.add("open");
};
$("#import-cancel").onclick=()=>$("#importmodal").classList.remove("open");
$("#import-confirm").onclick=async()=>{
  const body=(window._importEntries&&window._importEntries.length)
    ? {entries:window._importEntries}
    : {xml:window._importXml,commit:true};
  const r=await fetch("/api/import",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const j=await r.json(); $("#importmodal").classList.remove("open");
  if(r.ok){ toast(`Imported ${j.imported}`+(j.skipped_dupes?`, ${j.skipped_dupes} duplicate(s) skipped`:"")); load(); }
  else toast(j.error||"Import failed",true);
};
$("#export-btn").onclick=(e)=>{ e.stopPropagation(); $("#export-menu").classList.toggle("open"); };
document.addEventListener("click",()=>$("#export-menu").classList.remove("open"));
$("#export-menu").querySelectorAll("button").forEach(b=>b.onclick=()=>{
  const fmt=b.dataset.fmt==="xlsx-json"?"json":b.dataset.fmt;
  const p=filterParams(); p.set("format",fmt);
  window.location="/api/export?"+p.toString();
  $("#export-menu").classList.remove("open");
});
load();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    raise SystemExit(main())
