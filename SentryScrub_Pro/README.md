# Scrub (formerly SentryScrub)
### Vault-grade, offline PII anonymization & recovery engine for Law 25 and GDPR compliance.

**Scrub** is a high-performance, forensic-grade utility designed to sanitize sensitive datasets (CSV/JSON/NDJSON) before they leave your secure environment. Built with the **Polars** Rust-backed engine, it provides O(n) streaming anonymization with zero cloud dependencies.

---

## 🚀 Key Features

### 1. High-Performance Anonymization (`sscrub.py`)
- **Polars Engine:** Processes millions of rows in seconds using streaming (sink) mode, keeping RAM usage < 100MB even on hardware like a **Raspberry Pi 3B**.
- **Three-Tier Masking:**
  - `MASK`: Replaces characters with `*` while preserving string length.
  - `HASH`: Cryptographically secure SHA-256 salted hashing for consistent identifiers (e.g., emails).
  - `ENCRYPT`: Vault-grade AES-256-GCM authenticated encryption for recoverable data.
- **Auto-Discovery:** Scans file headers and automatically suggests masking strategies based on PII patterns.
- **Interactive Shell:** An advanced CLI mode for "learning" new data patterns and managing configurations in real-time.

### 2. Secure Data Recovery (`sunseal.py`)
- **Authorized Decryption:** Reverse the `ENCRYPT` strategy using your Master Key or a Session Key.
- **Authenticated Integrity:** Automatically detects if a single bit of encrypted data has been tampered with (Bit-Flipping protection).

### 3. Advanced Security Model
- **Ephemeral Session Keys (New):** Generate a one-time encryption key for a single file transfer. This key is displayed once and **never saved to disk**, ensuring that even if your computer is stolen, the transfer remains secure.
- **Forensic Memory Hygiene:** Sensitive keys are managed in mutable buffers and physically **zeroed out (wiped)** from the computer's RAM immediately after use.
- **Master Vault:** Standard encryption uses a 32-byte `master.key` and 16-byte `hash.salt` for persistent, secure local storage.

---

## 🛠️ Quick Start

### Setup Keys
```bash
python3 sscrub.py --generate-keys
```

### Anonymize a File
```bash
python3 sscrub.py -i sensitive_data.csv -o scrubbed.csv run
```

### Secure Transfer (Ephemeral Mode)
```bash
# Sender generates a one-time key
python3 sscrub.py -i sensitive.csv -o transfer.csv --ephemeral run

# Recipient unseals with the provided key
python3 sunseal.py -i transfer.csv -c "SSN" --key "YOUR_EPHEMERAL_KEY"
```

---

## ⚖️ Compliance & Ethics
- **Law 25 (Quebec):** Specifically designed to meet "Data Minimization" and "Anonymization" standards.
- **GDPR:** Supports "Right to be Forgotten" workflows and secure cross-border data transfers.
- **No Cloud:** 100% offline. Your data and your keys never leave your machine.
