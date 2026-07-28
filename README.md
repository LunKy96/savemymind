# SaveMyMind

A single-file local tool to remember how you triaged a vulnerability, so you don't have to figure it out twice.

If you spend time with OWASP Dependency-Check, Qualys, Trivy or similar, the pain is familiar: you dig into a finding, decide it's a false positive (or that it's real, or that you're accepting the risk for now), and a month later the same CVE pops up on another project and you're back to square one. That reasoning ends up scattered across tickets and suppression files, or just lost. SaveMyMind is a place to write it down once and get it back in a second.

You run it, a page opens in your browser, and you record each decision with a status, a short reason and, when it matters, an expiry date. Everything lives in one SQLite file sitting next to the script, so the data is yours, stays on your machine, and a backup is just a file copy.

## The idea: status, not a yes/no flag

The core of it is that every entry has a status: **false positive** (doesn't apply), **not a false positive** (real, must not be suppressed) or **waiver** (real, but the risk is accepted for now). That third one plus the "not a false positive" case are where the tool earns its keep. Six months later you meet the same CVE and instead of re-litigating it you already know it was checked, that it's genuinely exploitable, and that it must never land in a suppression file. That single note is the difference between a calm afternoon and an incident.

Waivers and false positives can also carry an expiry date, and there's a panel on the left that keeps an eye on what's about to lapse or is already overdue, sorted by urgency. An accepted risk that quietly expired eight months ago is exactly the kind of thing this is meant to stop.

## Running it

You need Python 3.8+ (already on macOS and Linux; a one-time install on Windows). Then:

```
python savemymind.py
```

First run creates `savemymind.db` next to the script, starts a tiny local server and opens the page at http://127.0.0.1:8765. Ctrl+C stops it, your data stays put. There's `--port`, `--no-browser` and `--db path` if you need them. No pip install, no Docker, no account, the whole UI is baked into the script.

A word on persistence, since it trips people up: the server only runs while the script runs, but the database is a plain file that never goes anywhere. Reboot, come back next week, run it again, everything's there. Back it up by copying `savemymind.db` (do it while the app is stopped, since SQLite in WAL mode keeps recent writes in the `-wal`/`-shm` side files), or hit Export for a snapshot.

## What you can do with it

Generate suppression XML per entry: false positives and waivers get a Copy XML button that puts a ready-to-paste block on your clipboard, using the expiry date as the `until` value when there is one. Entries flagged "not a false positive" deliberately have no such button, so they can't slip into a suppression file by accident.

Find things two ways. The box at the top searches the whole database as you type; below it there are proper filters for package, CVE/GHSA, CPE, SHA1, file path, author, status, expiry (soon / expired / still valid) and a created-date range with a calendar picker. By default the list only renders the 25 most recent entries to stay snappy and tells you how many more exist; the moment you search or filter, that cap goes away and you see every match.

Smaller things that add up: a copy button on every identifier in a row, an Export button that dumps whatever you're currently looking at (filters and all) to CSV, JSON or XML, a duplicate check that stops you and shows the existing record if you try to save the same CVE on the same package (great for catching the case where you're about to mark as a false positive something you'd already ruled real), and a per-entry change history so you can see that something started as a waiver and later became "not a false positive", with dates.

Package, CVE/GHSA and CPE are required; expiry, SHA1, file path, author and the description are optional. Created and updated timestamps are automatic.

## Privacy and internals

It listens on 127.0.0.1 only, loads nothing from the internet (no external fonts or scripts) and sends nothing anywhere, so it works fully offline. It's a single-user tool by design; if you ever host it somewhere shared, put authentication in front of it first. Under the hood it's one Python file using only the standard library (`http.server`, `sqlite3`, `json`, `csv`, `webbrowser`), a plain HTML/CSS/JS front end served locally, and two small SQLite tables (entries and history).

## License

MIT. See the LICENSE file.
