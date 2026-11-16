# URL-SAFE

A local-first security learning lab built with Python's standard library. The interface runs in your browser, while Python scanner classes perform the checks and SQLite stores scan history on your device.

## Run it

1. Install Python 3.10 or newer.
2. Open a terminal in this folder.
3. Run `python app.py`.
4. Your browser opens at `http://127.0.0.1:8765`.
5. Press `Ctrl+C` in the terminal to stop the app.

If port 8765 is already in use, set `URL_SAFE_PORT` before running. For example, in PowerShell: `$env:URL_SAFE_PORT=8766; python app.py`.

## Included

- URL checks for common suspicious patterns. The app never visits the URL.
- Filename and extension checks. File contents are never opened or uploaded.
- Local checks for common social-engineering phrases in text.
- Local password structure checks. Password samples are not saved or placed in reports.
- Risk score, findings, recommended next step, and downloadable JSON reports for saved URL and file scans.
- On-device SQLite history for URL and file scans.
- Three safe, simulated threat-lab scenarios.
- Python OOP scanner hierarchy: `SecurityScanner`, `URLScanner`, `FileScanner`, `PasswordScanner`, and `TextScanner`.

## Privacy and limits

The server binds to `127.0.0.1` and the app has no external service integration. Data stays in this folder in `url_safe.db`. Delete that file while the app is stopped to clear history. Google Fonts are referenced by the UI; if the network is unavailable, the interface falls back to system fonts.

Scores are educational heuristics, not proof that an item is malicious or safe. The app does not inspect file contents, visit URLs, check domain reputation, or replace antivirus software or a password manager.
