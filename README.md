# File-Integrity-Checker

🛡️ File Integrity Checker (Python)

A lightweight, fast, and dependency-free File Integrity Checker built in Python using hashlib.
It monitors files and directories for any changes by computing and comparing SHA-256 hashes, helping you detect tampering, corruption, malware, or accidental modification.

Perfect for developers, sysadmins, security analysts, and anyone who wants to keep track of file changes.

🚀 Features

✔️ Computes SHA-256 hash (secure & reliable)
✔️ Works on any OS (Windows / Linux / macOS)
✔️ Detects added, removed, and modified files
✔️ Creates a baseline snapshot of file hashes
✔️ Scans and compares current state with the baseline
✔️ Continuous monitoring mode with alerts
✔️ Exclude patterns (--exclude *.log)
✔️ Zero external dependencies — pure Python
✔️ JSON reporting support

📦 Installation

Just download or clone the repository:

git clone https://github.com/ChandraSekharGhosh/File-Integrity-Checker.git
cd file-integrity-checker


Run using Python 3.8+:

python file_integrity_checker.py --help


No dependencies required.

📘 How It Works

This tool creates a baseline JSON file containing SHA-256 hashes of every file in the selected directory.
When you scan or monitor, it recomputes all hashes and reports:

🔹 Files added

🔸 Files removed

🔥 Files modified

This ensures the integrity of your files and allows you to detect unexpected changes immediately.

📑 Usage Guide

Below are the essential commands users need to operate the tool.

🧱 1. Create a Baseline Snapshot

Build a baseline of all current files:

python file_integrity_checker.py init /path/to/dir --baseline baseline.json


This baseline contains:

SHA-256 hash

file size

last modification time

Use this baseline to detect changes later.

🔍 2. Scan and Compare Against Baseline

Check for any modifications:

python file_integrity_checker.py scan /path/to/dir --baseline baseline.json


Optional: save a detailed JSON report:

python file_integrity_checker.py scan /path/to/dir --baseline baseline.json --report report.json

🔄 3. Update Baseline

If you trust the new state and want it to be your new clean reference:

python file_integrity_checker.py update-baseline /path/to/dir --baseline baseline.json

📡 4. Monitor Directory Continuously

Poll directory changes every 15 seconds:

python file_integrity_checker.py monitor /path/to/dir --baseline baseline.json --interval 15


Enable automatic baseline update after detecting changes:

python file_integrity_checker.py monitor /path/to/dir --baseline baseline.json --interval 15 --autoupdate


Useful for:

monitoring log directories

watching system files

detecting tampering on servers

📁 5. Verify a Single File Against Known Hash

Check the SHA-256 of a file:

python file_integrity_checker.py verify-file myfile.txt


Compare with known hash:

python file_integrity_checker.py verify-file myfile.txt --hash <expected_hash>

🚫 Excluding Files or Folders

Exclude multiple patterns:

python file_integrity_checker.py scan /path --exclude "*.log" --exclude "node_modules/*"

⚙️ Command Help

Get full help anytime:

python file_integrity_checker.py --help

🧩 Example Use Cases

🔐 Detect unauthorized file modifications
🖥️ Monitor sensitive configuration files
📁 Track project file changes without Git
🦠 Spot suspicious changes caused by malware
📦 Verify file integrity during deployments

🛠️ Future Enhancements (Optional)

These improvements can be added later:

Digital signature for baseline (HMAC/PGP)

Real-time monitoring using watchdog

Email/SMS alerts on change

GUI dashboard

Integrity verification for remote servers

🤝 Contributing

Pull requests are welcome!
If you have suggestions, feel free to open an issue.
