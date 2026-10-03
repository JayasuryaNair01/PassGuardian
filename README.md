# 🔒 PassGuardian

**PassGuardian** is a lightweight, zero-dependency Command Line Interface (CLI) password security auditor written in Python. It combines local rule analysis, offline dictionary filtering, and privacy-preserving real-time breach intelligence via the HaveIBeenPwned API.

---

## ✨ Features

- **Privacy-Preserving Breach Checking (k-Anonymity):** Queries the HaveIBeenPwned API using SHA-1 prefix ranges (5 characters). Your plaintext password and remaining hash characters **never leave your local machine**.
- **Two-Tier Verification Engine:**
  1. **Offline Dictionary Filter:** Fast local checking against custom wordlists (e.g., RockYou subsets).
  2. **Online Intelligence:** Scans over 10 billion leaked credentials from real-world data breaches.
- **Interactive Terminal UI:** ANSI color formatting, progress visualizer, masked CLI inputs via `getpass`, and structured audit output cards.
- **Audit Logging:** Automatically logs session audit history to `password_log.txt` with strict password masking (`****`).
- **Zero Dependencies:** Built entirely with Python standard library modules (`hashlib`, `urllib`, `argparse`, `getpass`).

---

## 🛠️ Installation & Requirements

* **Python 3.8+**
* No external `pip` packages required!

```bash
git clone [https://github.com/JayasuryaNair01/PassGuardian.git](https://github.com/JayasuryaNair01/PassGuardian.git)
cd PassGuardian
