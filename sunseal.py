"""
sunseal v1.0 - The "Reverse Gear"
Recovery Utility for SentryScrub Authorized Personnel

Technical Specs:
- Support: -i, -o, -c CLI flags
- Paths: Automatic tilde (~) expansion
- Security: Forensic memory zeroing
"""

import os
import sys
import base64
import time
import polars as pl
from pathlib import Path
from Crypto.Cipher import AES

# --- SECURITY ---
KEY_FILE = "master.key"

def load_key() -> bytearray:
    # Look for key in current dir or parent (Pro setup)
    search_paths = [Path(KEY_FILE), Path("..") / KEY_FILE]
    for p in search_paths:
        if p.exists():
            with open(p, "rb") as f: return bytearray(f.read())
    
    print(f"[FATAL] Recovery Key '{KEY_FILE}' missing. Unsealing is impossible.")
    sys.exit(1)

def expand_path(p: str) -> Path:
    """Intelligently expands ~/ and relative paths."""
    if not p: return None
    return Path(os.path.expanduser(p)).resolve()

def safe_decrypt(payload_b64, key: bytearray):
    if payload_b64 is None: return None
    try:
        # Decode Base64 back to raw bytes
        raw_payload = base64.b64decode(payload_b64)
        
        # Extract components (Nonce 16, Tag 16, Ciphertext remaining)
        nonce = raw_payload[:16]
        tag = raw_payload[16:32]
        ciphertext = raw_payload[32:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except Exception:
        return "[UNSEAL_ERROR]"

def main():
    import argparse
    parser = argparse.ArgumentParser(description="sunseal - Authorized Data Recovery")
    parser.add_argument("-i", "--input", help="Scrubbed file to unseal")
    parser.add_argument("-o", "--output", help="Destination path for recovered data")
    parser.add_argument("-c", "--column", help="Name of the ENCRYPTED column to reverse")
    args = parser.parse_args()

    print("\n[sunseal] Initializing Authorized Recovery...")
    
    # Path Resolution logic
    in_path_raw = args.input if args.input else input("[?] Enter the scrubbed file path: ")
    in_path = expand_path(in_path_raw)

    if not in_path or not in_path.exists():
        print(f"[ERROR] Source file not found at: {in_path}")
        sys.exit(1)

    target_col = args.column if args.column else input("[?] Enter the name of the ENCRYPTED column: ")
    out_path_raw = args.output if args.output else "unsealed_recovery.csv"
    out_path = expand_path(out_path_raw)

    m_key = load_key()

    try:
        print(f"[*] Ingesting: {in_path.name}")
        
        # We use scan_csv to keep recovery memory-efficient as well
        suffix = in_path.suffix.lower()
        if suffix == ".json":
            df = pl.read_json(str(in_path))
        elif suffix == ".ndjson":
            df = pl.read_ndjson(str(in_path))
        else:
            df = pl.read_csv(str(in_path))
        
        if target_col not in df.columns:
            print(f"[ERROR] Column '{target_col}' not found in file headers.")
            return

        print(f"[*] Reversing AES-GCM layer for '{target_col}'...")
        start_time = time.time()
        
        df = df.with_columns(
            pl.col(target_col).map_elements(lambda x: safe_decrypt(x, m_key), return_dtype=pl.String)
        )
        
        # Save results
        df.write_csv(str(out_path))
        
        elapsed = time.time() - start_time
        print(f"\n[OK] SUCCESS: Data unsealed and saved to {out_path}")
        print(f"[*] Benchmarking: Recovered {len(df):,} rows in {elapsed:.2f} seconds.")
    
    except Exception as e:
        print(f"[FATAL] Recovery failed: {e}")

    finally:
        # Security Hygiene
        if 'm_key' in locals() and m_key:
            for i in range(len(m_key)): m_key[i] = 0
            print("[!] Forensic memory purge complete.")

if __name__ == "__main__":
    main()
