# Password Security Suite 🛡️

A beginner-friendly **web application** for exploring password security: analyze passwords, generate strong ones, and run safe, local simulations of common attacks and defenses.

The back end is **standard Java** (no external libraries): it uses the JDK's built-in HTTP server and security APIs. The front end is plain **HTML, CSS and JavaScript** served to your browser. Everything runs on your own computer at `http://localhost:8080`.

---

## Contents

1. [Quick start](#1-quick-start)
2. [Features (the 9 modules)](#2-features-the-9-modules)
3. [How it works](#3-how-it-works)
4. [Project structure](#4-project-structure)
5. [Automated tests](#5-automated-tests)
6. [Privacy and ethical boundaries](#6-privacy-and-ethical-boundaries)
7. [Future enhancements](#7-future-enhancements)

---

## 1. Quick start

**Requirements:** JDK 11 or newer (tested on JDK 26). Any modern browser.

### Windows
1. Double-click **`compile.bat`**.
2. Double-click **`run.bat`**. Your browser opens at `http://localhost:8080/`.
3. To stop, close the console window (or press `Ctrl+C` in it).

### macOS / Linux
```bash
./compile.sh
./run.sh
```

### Command line (any OS)
```bash
javac -d bin $(find src -name "*.java")
java -cp bin passwordsecurity.Main
```

Options: `--port 9090` to use another port (if 8080 is busy the app tries the next free one automatically), and `--no-browser` to skip opening a browser.

> Run the app from the project folder so it can find `web/` and `data/`.

---

## 2. Features (the 9 modules)

| # | Module | What you can do |
|---|--------|-----------------|
| 1 | **Password Strength Analyzer** | Live score (0-100), Weak/Medium/Strong rating, entropy (`E = L × log2(R)`), character checklist, crack-time estimate, and weak-pattern warnings (common words, `123`/`abc` runs, `aaa` repeats, short length). **Analyze & record** adds the score (never the password) to the session report. |
| 2 | **Secure Password Generator** | Random passwords (6-64 chars, choose character sets, exclude look-alikes `0 O l I 1`) and memorable passphrases (3-8 words, separator, capitalisation, trailing number). Uses `java.security.SecureRandom`. Shows entropy, copy-to-clipboard, and "Analyze it". |
| 3 | **Brute Force Simulator** | Type any target (up to 12 characters); the matching character sets are ticked automatically. Java guesses every combination of that length in order (aaa, aab, …) at full speed, roughly 50-300 million guesses per second, for up to 4 seconds. Shows pool size, `R^L`, attempts, time, measured speed, and how long a full search would take. Words up to about 6 lowercase letters are cracked; longer ones run out of time, which is the lesson. |
| 4 | **Dictionary Attack Simulator** | Walks the local wordlist `data/sample_words.txt` looking for the target, with animated/fast/instant speeds. Add your own words or restore the original list. |
| 5 | **Password Hashing Lab** | Compute SHA-256 of any text, plus three demos: **determinism**, the **avalanche effect** (shows exactly how many of the 256 bits flip), and **salting** (same password, different stored hashes). |
| 6 | **Hash Matching Demo** | Pick a "leaked" SHA-256 hash (or paste one) and watch candidate words get hashed and compared until one matches. Shows that hashes are guessed, not reversed. |
| 7 | **Login Security Demo** | Three demo accounts stored as salted **PBKDF2-HMAC-SHA256** (10,000 iterations, 16-byte salts). Failed-attempt tracking, **lockout after 3 failures**, a **15-second cooldown** with countdown, an emergency admin reset, and an authentication log. |
| 8 | **Reports & Analytics** | Session tiles (total analyzed, average score, Strong/Medium/Weak), strength-distribution chart, simulation counters, analysis history, and **Export report** (downloads a `.txt`). Only metadata is stored. |
| 9 | **Crack-Time Estimator** | Compare two passwords' search spaces and the average/worst-case time to exhaust them at five speeds: rate-limited website (10/s), CPU script (100k/s), slow KDF (1k/s), GPU rig (10 billion/s) and GPU cluster (1 trillion/s). |

The site also has a home dashboard, dark/light mode, and a layout that works on phones.

---

## 3. How it works

```
 Browser (HTML/CSS/JS)                      Java (JDK only)
 ─────────────────────                      ───────────────────────────────────────
 web/index.html   ──  fetch /api/...  ──▶   web/WebServer      (com.sun.net.httpserver)
 web/js/app.js    ◀──  JSON responses ──         │
 web/css/style.css                               ▼
                                            core/*  (all security logic, no UI code)
                                              PasswordAnalyzer, PasswordGenerator,
                                              AttackSimulations, Hashing, LoginService,
                                              CrackTimeEstimator, SessionStats, SecurityMath
```

- **All security logic lives in `passwordsecurity.core`** and has no UI code, so the same classes are used by the website and the tests.
- The server binds to **127.0.0.1 only**, rejects requests whose `Host` isn't localhost, and blocks path traversal on static files.
- Large keyspaces use `java.math.BigInteger`, so values like 95^64 never overflow.
- Simulations run on the server in milliseconds; the browser then replays the steps so you can watch them.

### API (for reference)

| Method | Route | Purpose |
|--------|-------|---------|
| POST | `/api/analyze` | Analyze a password (`record=1` to add it to stats) |
| POST | `/api/generate/password`, `/api/generate/passphrase` | Generate |
| POST | `/api/bruteforce/space`, `/api/bruteforce/run` | Brute-force maths and simulation |
| GET/POST | `/api/dictionary`, `/api/dictionary/add`, `/api/dictionary/reset`, `/api/dictionary/run` | Wordlist and attack |
| POST | `/api/hash`, `/api/hash/demo` | SHA-256 and demos |
| GET/POST | `/api/hashmatch`, `/api/hashmatch/run` | Hash matching |
| GET/POST | `/api/login/accounts`, `/api/login/status`, `/api/login`, `/api/login/reset` | Login demo |
| GET/POST | `/api/estimate/rates`, `/api/estimate` | Crack-time estimator |
| GET/POST | `/api/stats`, `/api/stats/reset`, `/api/report` | Analytics and report download |

---

## 4. Project structure

```
mini project/
├── src/passwordsecurity/
│   ├── Main.java                  # Starts the web server and opens the browser
│   ├── TestSuite.java             # 83 automated tests (core logic + HTTP API)
│   ├── core/
│   │   ├── PasswordAnalyzer.java  # Module 1: scoring, entropy, pattern checks
│   │   ├── PasswordGenerator.java # Module 2: SecureRandom passwords & passphrases
│   │   ├── AttackSimulations.java # Modules 3, 4, 6: brute force, dictionary, hash matching
│   │   ├── Hashing.java           # Module 5/7: SHA-256, PBKDF2, salts, bit-difference
│   │   ├── LoginService.java      # Module 7: accounts, failed attempts, lockout, cooldown
│   │   ├── SessionStats.java      # Module 8: metadata-only statistics and text report
│   │   ├── CrackTimeEstimator.java# Module 9: keyspace and times at 5 guessing speeds
│   │   ├── SecurityMath.java      # Shared pool/entropy/BigInteger/duration helpers
│   │   └── Wordlists.java         # Loads data/sample_words.txt; hash-demo samples
│   └── web/
│       ├── WebServer.java         # HTTP server, JSON API, static file serving
│       └── Json.java              # Tiny JSON writer (no libraries)
├── web/
│   ├── index.html                 # Single-page site with all 9 modules
│   ├── css/style.css              # Styling (light/dark, responsive)
│   └── js/app.js                  # Page logic: routing, API calls, animations
├── data/sample_words.txt          # Local educational wordlist
├── legacy-swing/                  # The original Java Swing version (kept for reference, not compiled)
├── compile.bat / run.bat / test.bat
├── compile.sh  / run.sh  / test.sh
└── pom.xml
```

---

## 5. Automated tests

```bash
java -cp bin passwordsecurity.TestSuite
```
(or double-click `test.bat`). The suite runs **83 checks** against the real production classes, then starts the web server on a random port and calls the API end to end:

- **Analyzer:** empty/short input, character classes, pool size, entropy, sequential and repeated patterns, common words
- **Generator:** length, every selected class present, randomness, exclude-ambiguous, invalid settings rejected, passphrase format and vocabulary
- **Brute force:** finds `429` at attempt #430, `R^L` maths, cracks a 5-letter word, stops at the attempt ceiling and at the time limit, out-of-pool characters rejected
- **Dictionary / hash matching:** found index, full-scan miss, case sensitivity, malformed hash rejected
- **Hashing:** SHA-256 known test vector, determinism, avalanche bit difference, salting
- **Login:** PBKDF2 determinism, lockout after exactly 3 failures, blocked while locked, cooldown expiry (simulated clock), emergency reset, success clears the counter
- **Stats / report / estimator:** counters, averages, report text, BigInteger overflow, duration formatting, 5-speed comparison
- **Web API:** every module's endpoint, 400 on bad input, path traversal blocked, and stats never contain a password

---

## 6. Privacy and ethical boundaries

- **No passwords are stored.** Analysis keeps only score, rating, entropy and crack-time. Passwords sent to the local server are processed in memory and never logged or written to disk.
- **Local only.** The server listens on `127.0.0.1`; nothing is sent to the internet. Attack simulations run against sample strings you type, never against real systems.
- **Demo accounts only:** `alice_student`, `bob_admin`, `charlie_guest`. Their passwords are shown on the page on purpose.
- **Estimates are theoretical.** Crack times assume a uniform brute-force search. Real attackers try dictionaries and patterns first, so weak-looking passwords can fall much faster.
- **Small passphrase vocabulary.** The demo generator uses a 54-word list (~5.8 bits per word), so the page labels short passphrases honestly as weak. Real generators use 7,776-word lists.

---

## 7. Future enhancements

- Argon2id / bcrypt / scrypt timing comparison alongside PBKDF2
- A larger passphrase vocabulary (e.g. the EFF long wordlist)
- HaveIBeenPwned k-anonymity demonstration (SHA-1 prefix range queries)
- Passkey (FIDO2/WebAuthn) walkthrough comparing passwords with public-key login

---

*Educational project for computer science and cybersecurity lab studies. Pure Java SE + HTML/CSS/JS, no external dependencies.*
"# miniproject" 
"# miniproject" 
