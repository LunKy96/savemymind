# SaveMyMind

A small local tool to keep track of the decisions you make while triaging vulnerabilities.

If you work with tools like OWASP Dependency-Check, Qualys or Trivy, you know the problem. You look into a finding, decide whether it is a real issue or a false positive, and a month later the same finding shows up on another project and you have to work it out all over again. Those decisions tend to get lost inside tickets, suppression files or your own memory.

SaveMyMind is where you write them down once and find them again in a second. You run it, a page opens in your browser, and you save each decision with a status, a reason and (when it matters) an expiry date. Everything lives in a single database file next to the script, so it stays yours, it stays local, and you back it up by copying one file.

## Statuses, not just a flag

Every entry has a status:

False positive for findings that do not apply.
Not a false positive for findings that are real and must not be suppressed.
Waiver for cases where the vulnerability is real but the risk has been accepted for now.

The value shows up later. Six months down the line you might run into the same CVE and, instead of guessing, you immediately see that it was already checked, that it is real, and that it should never go into a suppression file. That one note can save you from a bad mistake.

## Expiry and the side panel

A false positive or a waiver can carry an expiry date. On the left you get a live panel that lists everything that is expiring soon or already overdue, sorted by urgency, so nothing sits accepted and forgotten for months. Each entry shows how many days are left or how long it has been overdue, and clicking it opens the entry to review or extend it. Stats at the top also count how many entries are expiring soon and how many have expired.

## Suppression XML per entry

Entries marked as a false positive or a waiver get a Copy XML button on the entry itself, which copies a ready to paste suppression block to your clipboard. If the entry has an expiry date, that date goes into the block as the until value; otherwise a false positive is written without an expiry and a waiver gets a placeholder for you to fill in. Entries marked as not a false positive have no such button, which is the point: those must not end up in a suppression file.

## Running it

You only need Python 3.8 or newer, which is already there on macOS and Linux, and a one time install on Windows.

```
python savemymind.py
```

On the first run it creates a database file called savemymind.db next to the script, starts a small local server and opens the page in your browser at http://127.0.0.1:8765. Press Ctrl+C in the terminal to stop it. Your data stays in the file.

A few options if you need them:

```
python savemymind.py --port 9000
python savemymind.py --no-browser
python savemymind.py --db C:\path\to\my.db
```

No pip install, no Docker, no account. The whole interface is embedded in the script, so it really is a single file.

## Does my data survive a restart

Yes. There are two separate things here. The server runs only while the script is running, so if you close the terminal or shut down the machine the server stops. The database is a normal file on disk and it is never switched off. Stop everything, reboot, come back next week, run the script again and every entry is exactly where you left it.

To make a backup, copy savemymind.db somewhere safe, or use the Export button to download a snapshot. SQLite runs in WAL mode, so if you copy the file by hand do it while the app is stopped, otherwise the two side files (savemymind.db-wal and savemymind.db-shm) may still hold recent writes.

## Searching, filtering and viewing

By default the list shows only the 25 most recent entries, newest first, and tells you how many more are in the database. As soon as you search or filter, the limit is dropped and you see every match.

There are two ways to search. At the top there is a single box that filters as you type and looks across the whole database, handy when you only half remember what you are after. Below there are per field filters: package, CVE or GHSA, CPE, SHA1, file path, author, status, an expiry filter (expiring soon, expired, still valid) and a created date range. The date range uses a calendar picker.

## Quick actions

Every identifier in a row has a small copy button, so you can drop a CVE, a package, a CPE or a SHA1 straight into your clipboard. The Export button in the top right exports exactly what you are currently viewing, filters included, as CSV, JSON or XML, which is handy for reports or for moving data elsewhere.

## Duplicate warning

When you save a brand new entry, if the same CVE on the same package already exists SaveMyMind stops and shows you the existing entry. You can insert it anyway or cancel. This catches accidental duplicates and, more importantly, warns you if you are about to file as a false positive something you had already marked as not a false positive.

## Change history

Every entry keeps a history of its changes, especially status changes. Open an entry and you can see, for example, that it started as a waiver and later became not a false positive, with dates. Knowing when and how a decision changed is worth a lot months later.

## Fields

Package, CVE or GHSA, and CPE are required. The CVE or GHSA field just needs to hold whichever identifier you have. Expiry, SHA1, file path, author and the free text description are optional. The creation and last change dates are recorded automatically and shown on each entry, so there is no date to fill in by hand.

## Privacy

The server listens on 127.0.0.1 only, so it is not reachable from your network. Nothing is sent anywhere, and no fonts or scripts are loaded from the internet, so it works fully offline. It is built for a single person on their own machine. If you ever want to put it on a shared host, add authentication first.

## Under the hood

One Python file, standard library only (http.server, sqlite3, json, csv, webbrowser). The interface is plain HTML, CSS and JavaScript served locally, and SQLite handles storage in WAL mode with two small tables, one for entries and one for the change history.

## License

MIT. See the LICENSE file.
