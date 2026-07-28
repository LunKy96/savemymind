# SaveMyMind

<img width="1309" height="477" alt="immagine" src="https://github.com/user-attachments/assets/86568911-0e5d-4252-a3f6-368a8038dfd4" />


A single-file local tool to keep track of how you triaged a vulnerability, so you don't have to work it out again next time.

Anyone using OWASP Dependency-Check, Qualys, Trivy or similar knows the problem. You dig into a finding, decide it's a false positive (or that it's real, or that you're accepting the risk for now), then a month later the same CVE turns up on another project. You start over, because that decision got scattered across tickets and suppression files, or lost. SaveMyMind is where you write it down once and get it back in a second.

You run it, a page opens in your browser, you record each decision with a status, a short reason and, where it matters, an expiry date. Everything goes into one SQLite file next to the script. The data stays yours and on your machine. A backup is just a copy of that file.

## Statuses

Every entry has a status: false positive (does not apply), not a false positive (real, must not be suppressed) or waiver (real, but the risk is accepted for now). The last two are the ones that matter most. Six months later you meet the same CVE and already know it was checked, that it's genuinely exploitable, that it must not go into any suppression file. That note is what stops you from suppressing a real vulnerability by mistake.

False positives and waivers can carry an expiry date. A panel on the left lists what is about to expire or already overdue, sorted by urgency, so an accepted risk doesn't sit there forgotten for months.

## Running it

You need Python 3.8 or newer. It's already on macOS and Linux; on Windows it's a one-time install. Then:

```
python savemymind.py
```

First run creates savemymind.db next to the script, starts a small local server, opens the page at http://127.0.0.1:8765. Ctrl+C stops it, the data stays. There are --port, --no-browser and --db path options if you need them. No pip install, no Docker, no account. The whole interface lives inside the script.

One thing about persistence, since it trips people up. The server runs only while the script runs, but the database is a plain file that doesn't disappear. Reboot, come back next week, run the script again, everything is there. To back up, copy savemymind.db while the app is stopped (SQLite in WAL mode keeps recent writes in the -wal and -shm side files), or use the Export button.

## What you can do with it

Generate the suppression XML for a single entry. False positives and waivers have a Copy XML button that puts a ready-to-paste block on your clipboard. If the entry has an expiry date, that date becomes the until value. Entries marked not a false positive have no button, so you can't suppress them by mistake.

Import an existing suppression file. The Import button next to Export reads a Dependency-Check suppression.xml and turns every suppress block into an entry, pulling the package, the CVE or GHSA, the notes, the CPE, the SHA1 and the until date when they are there. It works out the status from the wording of the notes and the comment above each block (it recognises false positive, waiver and not-a-false-positive in Italian and English, and falls back to false positive when nothing is stated), while the until date is imported as the expiry. It shows a preview of what it found before writing anything, and skips blocks with no CVE and entries you already have. Handy if you arrive with years of suppressions already written.

Search in two ways. The box at the top searches the whole database as you type. Below it are filters for package, CVE/GHSA, CPE, SHA1, file path, author, status, expiry (expiring soon, expired, still valid) and a created-date range with a calendar picker. By default the list shows only the 25 most recent entries to stay fast, telling you how many more exist. As soon as you search or filter, that limit is gone and you see every match.

Other useful bits. A copy button on every identifier in a row. An Export button that downloads what you're currently viewing, filters included, as CSV, JSON or XML. A duplicate check that stops you and shows the existing entry if you try to save the same CVE on the same package, which catches the case where you're about to mark as a false positive something you already ruled real. A change history on every entry, with dates, so you can see how it changed over time, for example from waiver to not a false positive.

Only CVE/GHSA is required. Package, CPE, expiry, SHA1, file path, author and description are optional, which keeps quick notes quick. Created and updated dates are automatic.

## Getting the most out of it

Only CVE/GHSA is required, so you're never blocked when you jot down a quick note or import a file. That doesn't mean the other fields are pointless. The more you put into an entry, the more it's worth when you come back to it.

Package and CPE say what the decision was about. An entry with just CVE-2020-8203 tells you little six months later; the same entry with pkg:npm/lodash@4.17.15 and the CPE tells you which library and which context you judged. They also make the Copy XML output better: with a package the generated suppress block is targeted, without one it's weaker. SHA1 makes the match more precise still, pinning the exact artifact. The description is the one that matters most, because it's the why. Without a reason you won't trust your own past call and you'll end up redoing the analysis, which is the whole thing this tool is meant to avoid.

Rule of thumb: keep the required field minimal, but fill in as much as you have. Always write the reason, and add package and CPE whenever you know them.

## Privacy and internals

It listens on 127.0.0.1 only, so it's not reachable from your network. It loads nothing from the internet and sends data nowhere, so it works fully offline. It's meant for a single user on a single machine. If you ever put it on a shared host, add authentication in front of it first. Internally it's one Python file using only the standard library (http.server, sqlite3, json, csv, webbrowser), a plain HTML/CSS/JS front end served locally, two small SQLite tables (entries and history).

## License

MIT. See the LICENSE file.
