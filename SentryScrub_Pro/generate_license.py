#!/usr/bin/env python3
"""
generate_license.py
Utility script to generate Ed25519 key pairs and construct offline signed licenses for SentryScrub.
"""

import sys
import os
import json
import base64
import argparse
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519

PRIVATE_KEY_FILE = "license_private.key"

def load_or_create_keys():
    if os.path.exists(PRIVATE_KEY_FILE):
        with open(PRIVATE_KEY_FILE, "rb") as f:
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
        public_key = private_key.public_key()
    else:
        print("[*] Generating a new Ed25519 key pair...")
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Save private key raw bytes
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes_raw())
        print(f"[OK] Private key saved to: {PRIVATE_KEY_FILE}")
        
    pub_bytes = public_key.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode('ascii')
    print(f"\n[IMPORTANT] Copy this public key to hardcode in sscrub.py:")
    print(f"PUBLIC_KEY_B64 = \"{pub_b64}\"")
    print("-" * 60 + "\n")
    return private_key

def generate_license(private_key, email, org, tier, issued_date, keep_record):
    payload = {
        "email": email,
        "org": org,
        "tier": tier,
        "issued": issued_date,
        "keep_record": keep_record
    }
    
    # Minify JSON and encode to bytes
    json_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
    
    # Sign the bytes
    signature = private_key.sign(json_bytes)
    
    # Encode both payload and signature to urlsafe base64 without padding
    payload_b64 = base64.urlsafe_b64encode(json_bytes).decode('ascii').rstrip('=')
    signature_b64 = base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')
    
    license_key = f"{payload_b64}.{signature_b64}"
    
    print("--- LICENSE GENERATED ---")
    print(f"Licensee Email: {email}")
    print(f"Organization:   {org}")
    print(f"Tier:           {tier}")
    print(f"Issued Date:    {issued_date}")
    print(f"Keep Record:    {keep_record}")
    print("\nPaste the following license key in the CLI:")
    print(license_key)
    print("-------------------------")
    return license_key

def main():
    parser = argparse.ArgumentParser(description="Generate offline licenses for SentryScrub")
    parser.add_argument("--email", required=True, help="Customer email address")
    parser.add_argument("--org", required=True, help="Customer organization name")
    parser.add_argument("--tier", default="Commercial Perpetual", help="License tier/type")
    parser.add_argument("--issued", default=datetime.utcnow().strftime("%Y-%m-%d"), help="Issue date (YYYY-MM-DD)")
    parser.add_argument("--keep-record", choices=["y", "n"], help="Keep record of files exported (y/n)")
    args = parser.parse_args()

    keep_rec_val = args.keep_record
    if keep_rec_val is None:
        try:
            choice = input("Keep export history for this license? (y/N): ").strip().lower()
            keep_rec_val = "y" if choice in ["y", "yes"] else "n"
        except (KeyboardInterrupt, EOFError):
            keep_rec_val = "n"
    
    keep_record = (keep_rec_val == "y")

    private_key = load_or_create_keys()
    generate_license(private_key, args.email, args.org, args.tier, args.issued, keep_record)

if __name__ == "__main__":
    main()
