"""
sscrub (Community Edition) v1.0
Hardened Offline Anonymization Engine for Law 25 / GDPR Compliance

Operational Requirements:
- Ingestion: Polars LazyFrame (Memory O(n))
- Encryption: AES-256-GCM (Authenticated)
- Hygiene: Mutable bytearray mutation within finally block
- UX: Vault-Grade Terminal Heartbeat & Optional Interactive Shell
- Formats: Intelligent CSV/JSON/NDJSON Export
- Custom Intelligence: Persistent discovery_rules.yaml
"""

import json
import time
import os
import sys
import yaml
import hashlib
import base64
import gc
import re
import shlex
import atexit
import polars as pl
from pathlib import Path
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# --- CONSTANTS ---
KEY_FILE = "master.key"
SALT_FILE = "hash.salt"
CONFIG_FILE = "config.yaml"
DISCOVERY_RULES_FILE = "discovery_rules.yaml"
AUDIT_LOG = "scrub_audit.json"

# --- DEFAULT DISCOVERY RULES ---
DEFAULT_RULES = {
    "strategies": {
        "MASK":    ["name", "client", "user", "owner", "address", "phone", "balance", "amount", "salary"],
        "HASH":    ["email", "login", "username", "ip_address", "id"],
        "ENCRYPT": ["sin", "ssn", "tax_id", "passport", "license", "credit_card", "bank_account"]
    },
    "ignored_headers": []
}

# --- COMMON SENSE UTILITIES ---

PUBLIC_KEY_B64 = "N17molbSKMKChymxDZU5P2ojYMHqzOlsFm7/FdXDNys="
LICENSE_DIR = Path(os.path.expanduser("~/.config/sscrub")).resolve()
LICENSE_FILE = LICENSE_DIR / "license.json"
SESSION_FILES_LOG = LICENSE_DIR / "session_files.json"
LICENSE_HISTORY_FILE = LICENSE_DIR / "license_history.json"
IS_PRO_EDITION = False
LICENSE_INFO = None

def log_session_file(file_path: Path):
    license_id = "Community Edition"
    keep_record = False
    if IS_PRO_EDITION and LICENSE_INFO:
        license_id = LICENSE_INFO.get('email') or LICENSE_INFO.get('org') or "Pro Edition"
        keep_record = LICENSE_INFO.get('keep_record', False)
    
    if keep_record:
        # Persistent history record
        history_data = {}
        if LICENSE_HISTORY_FILE.exists():
            try:
                with open(LICENSE_HISTORY_FILE, "r") as f:
                    history_data = json.load(f)
            except Exception:
                pass
        if license_id not in history_data:
            history_data[license_id] = []
        abs_str = str(file_path.resolve())
        if abs_str not in history_data[license_id]:
            history_data[license_id].append(abs_str)
        try:
            LICENSE_DIR.mkdir(parents=True, exist_ok=True)
            with open(LICENSE_HISTORY_FILE, "w") as f:
                json.dump(history_data, f, indent=2)
        except Exception as e:
            print(f"[!] Warning: Failed to write to license history: {e}")
    else:
        # Transient session record (cleared at exit)
        data = {}
        if SESSION_FILES_LOG.exists():
            try:
                with open(SESSION_FILES_LOG, "r") as f:
                    data = json.load(f)
            except Exception:
                pass
        if license_id not in data:
            data[license_id] = []
        abs_str = str(file_path.resolve())
        if abs_str not in data[license_id]:
            data[license_id].append(abs_str)
        try:
            LICENSE_DIR.mkdir(parents=True, exist_ok=True)
            with open(SESSION_FILES_LOG, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[!] Warning: Failed to write to session log: {e}")

def clear_session_files():
    try:
        if SESSION_FILES_LOG.exists():
            with open(SESSION_FILES_LOG, "w") as f:
                json.dump({}, f)
    except Exception:
        pass

atexit.register(clear_session_files)

def verify_license_key(license_key: str) -> dict:
    if not license_key:
        return None
    try:
        parts = license_key.strip().split('.')
        if len(parts) != 2:
            return None
        payload_b64, signature_b64 = parts
        
        # Add padding back to base64 if needed
        payload_pad = payload_b64 + '=' * (4 - len(payload_b64) % 4) if len(payload_b64) % 4 else payload_b64
        sig_pad = signature_b64 + '=' * (4 - len(signature_b64) % 4) if len(signature_b64) % 4 else signature_b64
        
        json_bytes = base64.urlsafe_b64decode(payload_pad.encode('ascii'))
        signature = base64.urlsafe_b64decode(sig_pad.encode('ascii'))
        
        # Load public key
        pub_bytes = base64.b64decode(PUBLIC_KEY_B64.encode('ascii'))
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        
        # Verify signature
        public_key.verify(signature, json_bytes)
        
        # Parse payload
        payload = json.loads(json_bytes.decode('utf-8'))
        return payload
    except Exception:
        return None

def load_and_verify_license() -> dict:
    search_paths = [Path("license.json"), LICENSE_FILE]
    for p in search_paths:
        if p.exists():
            try:
                with open(p, "r") as f:
                    content = f.read().strip()
                try:
                    js = json.loads(content)
                    key = js.get("license_key", "").strip()
                except Exception:
                    key = content
                
                payload = verify_license_key(key)
                if payload:
                    return payload
            except Exception:
                pass
    return None

def initialize_licensing():
    global IS_PRO_EDITION, LICENSE_INFO
    payload = load_and_verify_license()
    if payload:
        IS_PRO_EDITION = True
        LICENSE_INFO = payload

def print_banner(shell=False):
    global IS_PRO_EDITION, LICENSE_INFO
    edition = "Pro Edition" if IS_PRO_EDITION else "Community Edition"
    title = f"🛡️ SentryScrub ({edition}) v1.0"
    print(f"\n{title}")
    if IS_PRO_EDITION:
        print(f"Licensed to {LICENSE_INFO['org']} ({LICENSE_INFO['email']})")
    else:
        print("Unlicensed for commercial use. Get Pro at sscrub.com (CAD $149)")
    
    if shell:
        print("Type 'help' for commands, 'run' to execute, or 'exit' to quit.\n")
    else:
        print("-" * 60)

def expand_path(p: str) -> Path:
    if not p: return None
    return Path(os.path.expanduser(p)).resolve()

def get_versioned_path(base_path: Path) -> Path:
    if not base_path.exists(): return base_path
    counter = 1
    while True:
        new_path = base_path.parent / f"{base_path.stem}({counter}){base_path.suffix}"
        if not new_path.exists(): return new_path
        counter += 1

# --- PERSISTENT RULES ENGINE ---

def load_discovery_rules():
    """Loads custom discovery rules or returns defaults."""
    if os.path.exists(DISCOVERY_RULES_FILE):
        try:
            with open(DISCOVERY_RULES_FILE, "r") as f:
                return yaml.safe_load(f)
        except Exception:
            pass
    return DEFAULT_RULES

def save_discovery_rules(rules):
    with open(DISCOVERY_RULES_FILE, "w") as f:
        yaml.dump(rules, f, default_flow_style=False)

# --- SECURITY ---

def generate_vault_keys():
    print("[*] Initializing Key Ceremony...")
    if os.path.exists(KEY_FILE) or os.path.exists(SALT_FILE):
        confirm = input("[!] WARNING: Keys already exist. Overwrite? (y/N): ")
        if confirm.lower() != 'y': return
    with open(KEY_FILE, "wb") as f: f.write(get_random_bytes(32))
    with open(SALT_FILE, "wb") as f: f.write(get_random_bytes(16))
    print(f"[OK] Keys Generated: {KEY_FILE}, {SALT_FILE}")

def load_vault_material(ephemeral=False):
    m_salt = bytearray()
    
    salt_path = Path(SALT_FILE)
    if not salt_path.exists():
        home_salt = Path(os.path.expanduser("~/hash.salt"))
        if home_salt.exists():
            salt_path = home_salt
            
    if salt_path.exists():
        with open(salt_path, "rb") as f: m_salt = bytearray(f.read())
    else:
        m_salt = bytearray(b"scrub_default_salt_2026")

    if ephemeral:
        e_key = bytearray(get_random_bytes(32))
        e_key_b64 = base64.urlsafe_b64encode(e_key).decode('ascii')
        
        border = "!" * 62
        print(f"\n{border}")
        print("  EPHEMERAL SESSION KEY GENERATED")
        print(border)
        print(f"\n  KEY: {e_key_b64}\n")
        print("  THIS KEY IS NOT SAVED TO DISK. IF YOU LOSE IT, THE DATA")
        print("  ENCRYPTED IN THIS SESSION IS PERMANENTLY UNRECOVERABLE.")
        print(border + "\n")
        
        input("  Press ENTER to confirm you have copied the key... ")
        return e_key, m_salt

    key_path = Path(KEY_FILE)
    if not key_path.exists():
        home_key = Path(os.path.expanduser("~/master.key"))
        if home_key.exists():
            key_path = home_key

    if not key_path.exists():
        print(f"[ERROR] Keys missing. Run: --generate-keys")
        return None, None
    with open(key_path, "rb") as f: m_key = bytearray(f.read())
    return m_key, m_salt

def secure_mem_wipe(ba: bytearray):
    if ba:
        for i in range(len(ba)): ba[i] = 0

# --- GOVERNANCE ---

def generate_audit_log(config, rows, elapsed_time=None, status="SECURED"):
    try:
        input_file = str(config['input_file'])
        input_hash = hashlib.sha256(Path(input_file).read_bytes()).hexdigest()
        audit_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operator": os.getlogin() if hasattr(os, 'getlogin') else "unknown",
            "input_file": input_file,
            "input_sha256": input_hash,
            "rows_processed": rows,
            "elapsed_seconds": round(elapsed_time, 2) if elapsed_time else None,
            "status": status
        }
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(audit_data) + "\n")
        print(f"[*] Audit record appended to {AUDIT_LOG}")
    except Exception as e:
        print(f"[!] Warning: Failed to generate audit log: {e}")

# --- STRATEGIES ---

def safe_mask(val):
    if val is None: return None
    s = str(val)
    return f"{s[0]}{'*' * (len(s)-2)}{s[-1]}" if len(s) > 2 else "***"

def safe_hash(val, salt: bytearray):
    if val is None: return None
    h = hashlib.sha256()
    h.update(salt)
    h.update(str(val).encode('utf-8'))
    return h.hexdigest()[:16]

def safe_encrypt(val, key: bytearray):
    if val is None: return None
    try:
        # Use 16-byte nonce for consistency with sunseal recovery
        nonce = get_random_bytes(16)
        # Ensure key is a raw bytes object
        cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(str(val).encode('utf-8'))
        # sunseal.py: raw_payload = base64.b64decode(payload_b64)
        # nonce = raw_payload[:16], tag = raw_payload[16:32], ciphertext = raw_payload[32:]
        payload = base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
        return payload
    except Exception as e:
        return f"[ENCRYPT_ERROR: {e}]"

# --- CONFIG ASSISTANT ---

def excel_col_to_index(col_str: str) -> int:
    num = 0
    for char in col_str.upper():
        if 'A' <= char <= 'Z':
            num = num * 26 + (ord(char) - ord('A') + 1)
    return num - 1 if num > 0 else 0

def parse_range(range_str: str) -> tuple[int, int, int, int]:
    m = re.match(r"([A-Z]+)(\d+):([A-Z]+)(\d+)", range_str.upper())
    if not m: return None
    sc_str, sr_str, ec_str, er_str = m.groups()
    return (
        excel_col_to_index(sc_str),
        int(sr_str) - 1,
        excel_col_to_index(ec_str),
        int(er_str) - 1
    )

def resolve_column_name(input_file: Path, col_ref: str) -> str:
    try:
        df_head = pl.read_csv(str(input_file), n_rows=1)
        headers = df_head.columns
        
        # 1. Try direct match first (Case-insensitive)
        for h in headers:
            if h.lower() == col_ref.lower(): return h
            
        # 2. Try index or Excel notation
        idx = int(col_ref) - 1 if col_ref.isdigit() else excel_col_to_index(col_ref)
        if 0 <= idx < len(headers): return headers[idx]
        
        print(f"[ERROR] Column '{col_ref}' not found or out of bounds.")
        return None
    except Exception as e:
        print(f"[FATAL] Could not read headers: {e}")
        return None

def update_yaml_config(cfg):
    out_cfg = cfg.copy()
    if isinstance(out_cfg.get('input_file'), Path): out_cfg['input_file'] = str(out_cfg['input_file'])
    if isinstance(out_cfg.get('output_file'), Path): out_cfg['output_file'] = str(out_cfg['output_file'])
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(out_cfg, f, default_flow_style=False)

def run_discovery(input_file_override=None, range_str=None):
    rules = load_discovery_rules()
    
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f: cfg = yaml.safe_load(f)
    else:
        cfg = {"input_file": input_file_override, "output_file": "scrubbed.csv", "columns_to_scrub": []}
    
    in_raw = input_file_override if input_file_override else cfg.get('input_file', '')
    input_file = expand_path(in_raw)
    
    if not input_file or not input_file.exists():
        print(f"[ERROR] Input file '{in_raw}' not found.")
        return

    df_head = pl.read_csv(str(input_file), n_rows=1)
    headers = df_head.columns
    if range_str:
        rng = parse_range(range_str)
        if rng:
            sc, _, ec, _ = rng
            headers = headers[sc:ec+1]

    found_any = False
    print(f"\n[sscrub] Running Discovery (Patterns: {len(rules['strategies']['MASK'])+len(rules['strategies']['HASH'])+len(rules['strategies']['ENCRYPT'])})")
    
    for header in headers:
        if header in rules.get('ignored_headers', []): continue
        
        h_lower = header.lower()
        for strategy, keywords in rules['strategies'].items():
            if any(k in h_lower for k in keywords):
                if not any(c['name'] == header for c in cfg.setdefault('columns_to_scrub', [])):
                    print(f"  [+] Match: '{header}' -> {strategy}")
                    cfg['columns_to_scrub'].append({'name': header, 'strategy': strategy})
                    found_any = True
                break
    
    if found_any:
        update_yaml_config(cfg)
        print(f"[OK] {CONFIG_FILE} updated.")
    else:
        print("[*] No new sensitive columns detected.")

# --- PIPELINE ---

def execute_scrub(args, config):
    if not config.get('columns_to_scrub'):
        print("\n[SAFETY ERROR] No columns are configured to be scrubbed. Processing halted to prevent accidental PII leakage.")
        print("[*] Run: python3 sscrub.py discover  to auto-detect columns, or configure config.yaml.")
        return
    m_key, m_salt = load_vault_material(ephemeral=args.ephemeral)
    if not m_key: return
    try:
        input_path = expand_path(config['input_file'])
        lf = pl.scan_csv(str(input_path))
        if args.range:
            rng = parse_range(args.range)
            if rng:
                sc, sr, ec, er = rng
                headers = pl.read_csv(str(input_path), n_rows=1).columns
                lf = lf.select(headers[sc:ec+1]).slice(sr, (er - sr + 1) if er else None)

        row_count = lf.select(pl.len()).collect().item()
        if not IS_PRO_EDITION and row_count > 50000:
            print(f"\n[LIMIT ERROR] SentryScrub Community Edition is limited to 50,000 rows (dataset has {row_count:,} rows).")
            print("[*] Please register a commercial license by running: sscrub --register <key>")
            return

        schema = lf.collect_schema().names()
        print("\n" + "-"*30 + f"\nVAULT SUMMARY {'(TURBO)' if args.turbo else '(STREAMING)'}\n" + "-"*30)
        print(f"Rows:    {row_count:,}\nColumns: {', '.join(schema)}\n" + "-"*30 + "\n")
        
        start_time = time.time()
        for col_conf in config['columns_to_scrub']:
            name = col_conf['name']
            strategy = col_conf['strategy'].upper()
            if name not in schema: continue
            print(f"[*] Locking: {strategy} -> {name}")
            if strategy == "MASK": lf = lf.with_columns(pl.col(name).map_elements(safe_mask, return_dtype=pl.String))
            elif strategy == "HASH": lf = lf.with_columns(pl.col(name).map_elements(lambda x: safe_hash(x, m_salt), return_dtype=pl.String))
            elif strategy == "ENCRYPT": lf = lf.with_columns(pl.col(name).map_elements(lambda x: safe_encrypt(x, m_key), return_dtype=pl.String))

        final_out = expand_path(config['output_file'])
        if final_out.is_dir(): final_out = final_out / "scrubbed.csv"
        if not args.force: final_out = get_versioned_path(final_out)
        
        suffix = final_out.suffix.lower()
        if args.turbo:
            df = lf.collect()
            if suffix == ".json": df.write_json(str(final_out))
            elif suffix == ".ndjson": df.write_ndjson(str(final_out))
            else: df.write_csv(str(final_out))
        else:
            if suffix == ".ndjson": lf.sink_ndjson(str(final_out))
            elif suffix == ".json": lf.collect().write_json(str(final_out))
            else: lf.sink_csv(str(final_out))
        
        elapsed = time.time() - start_time
        print(f"\n[OK] SUCCESS: Data saved to {final_out}")
        log_session_file(final_out)
        print(f"[*] Time: {elapsed:.2f} seconds.")
        generate_audit_log(config, row_count, elapsed_time=elapsed)
    except Exception as e: print(f"\n[FATAL ERROR] Pipeline stalled: {str(e)}")
    finally:
        secure_mem_wipe(m_key); secure_mem_wipe(m_salt); gc.collect()

# --- SHELL MODE ---

def run_shell(parser):
    print_banner(shell=True)
    while True:
        try:
            cmd_line = input("sscrub> ")
            if not cmd_line.strip(): continue
            cmd_args = shlex.split(cmd_line)
            try: args, _ = parser.parse_known_args(cmd_args)
            except SystemExit: continue
            
            if args.command == "exit": break
            if args.command == "help":
                print("\nCommands:")
                print("  discover [-i INPUT] [--range RANGE]   Auto-detect columns")
                print("  add -c COL -s STRATEGY                Add a rule to config.yaml")
                print("  remove -c COL                         Remove rule from config.yaml")
                print("  ignore -c HEADER                      Stop discovery from suggesting this header")
                print("  learn -k KEYWORD -s STRATEGY          Teach discovery a new pattern")
                print("  run [-i INPUT] [-o OUTPUT] [--turbo]  Execute the pipeline")
                print("  exit                                  Quit\n")
                continue
            
            if args.command == "ignore":
                if not args.column: print("[ERROR] ignore requires -c HEADER"); continue
                rules = load_discovery_rules()
                if args.column not in rules['ignored_headers']:
                    rules['ignored_headers'].append(args.column)
                    save_discovery_rules(rules)
                    print(f"[*] Discovery will now ignore header: '{args.column}'")
                continue

            if args.command == "learn":
                if not args.keyword or not args.strategy: print("[ERROR] learn requires -k KEYWORD -s STRATEGY"); continue
                rules = load_discovery_rules()
                rules['strategies'][args.strategy].append(args.keyword.lower())
                save_discovery_rules(rules)
                print(f"[+] Discovery learned: '{args.keyword}' -> {args.strategy}")
                continue

            if args.command == "discover":
                run_discovery(args.input, args.range); continue
            if args.command == "add":
                with open(CONFIG_FILE, "r") as f: cfg = yaml.safe_load(f)
                col_name = resolve_column_name(expand_path(args.input if args.input else cfg.get('input_file')), args.column)
                if col_name:
                    cfg.setdefault('columns_to_scrub', []).append({'name': col_name, 'strategy': args.strategy})
                    update_yaml_config(cfg); print(f"[+] Added: '{col_name}' -> {args.strategy}")
                continue
            if args.command == "remove":
                with open(CONFIG_FILE, "r") as f: cfg = yaml.safe_load(f)
                col_name = resolve_column_name(expand_path(args.input if args.input else cfg.get('input_file')), args.column)
                if col_name:
                    cfg['columns_to_scrub'] = [c for c in cfg.get('columns_to_scrub', []) if c['name'] != col_name]
                    update_yaml_config(cfg); print(f"[-] Removed rule for '{col_name}'.")
                continue
            if args.command == "run":
                if os.path.exists(CONFIG_FILE):
                    with open(CONFIG_FILE, "r") as f: config = yaml.safe_load(f)
                else: config = {"input_file": args.input, "output_file": "scrubbed.csv", "columns_to_scrub": []}
                if args.input: config['input_file'] = args.input
                if args.output: config['output_file'] = args.output
                if config.get('input_file'): execute_scrub(args, config)
                else: print("[ERROR] No input specified.")
                continue
        except (EOFError, KeyboardInterrupt): break

# --- MAIN ---

def main():
    import argparse
    parser = argparse.ArgumentParser(description="sscrub - Vault-Grade Data Anonymization", add_help=True)
    parser.add_argument("-i", "--input", help="Input CSV/JSON file")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-k", "--keyword", help="Keyword for discovery or learning")
    parser.add_argument("--generate-keys", action="store_true", help="Initialize master.key and hash.salt")
    parser.add_argument("--discover", action="store_true", help="Auto-detect sensitive columns")
    parser.add_argument("--range", help="Limit processing to Excel range (e.g. A1:C10)")
    parser.add_argument("--turbo", action="store_true", help="In-memory processing (faster, higher RAM)")
    parser.add_argument("--force", action="store_true", help="Overwrite output if it exists")
    parser.add_argument("--ephemeral", action="store_true", help="Use a one-time session key (not saved to disk)")
    parser.add_argument("--shell", action="store_true", help="Enter interactive mode")
    parser.add_argument("command", nargs="?", choices=["add", "remove", "ignore", "learn", "exit", "help", "run", "discover", "register"], help="Optional command to execute")
    parser.add_argument("-c", "--column", help="Target column for add/remove/ignore")
    parser.add_argument("-s", "--strategy", choices=["MASK", "HASH", "ENCRYPT"], help="Strategy for add/learn")
    parser.add_argument("--register", help="Register a license key string")
    
    initialize_licensing()

    # If no arguments or --shell, enter interactive mode
    if len(sys.argv) == 1 or "--shell" in sys.argv:
        run_shell(parser)
        sys.exit(0)

    args = parser.parse_args()

    # Handle license registration subcommand/flag
    if args.command == "register" or args.register:
        key_to_reg = args.register if args.register else input("[?] Enter your license key: ")
        payload = verify_license_key(key_to_reg)
        if not payload:
            print("[ERROR] Invalid license key signature. Registration failed.")
            sys.exit(1)
            
        # Display previous license's history if keep_record was active
        if LICENSE_FILE.exists():
            try:
                with open(LICENSE_FILE, "r") as f:
                    old_js = json.load(f)
                old_key = old_js.get("license_key", "").strip()
                old_payload = verify_license_key(old_key)
                if old_payload and old_payload.get("keep_record"):
                    old_email = old_payload.get("email") or old_payload.get("org") or "Pro Edition"
                    if LICENSE_HISTORY_FILE.exists():
                        with open(LICENSE_HISTORY_FILE, "r") as f:
                            history = json.load(f)
                        if old_email in history and history[old_email]:
                            print("\n" + "="*60)
                            print("[SECURITY AUDIT] Export History for Previous License:")
                            print(f"Licensee: {old_payload.get('org')} ({old_payload.get('email')})")
                            print("Files Exported:")
                            for file_path in history[old_email]:
                                print(f"  - {file_path}")
                            print("="*60 + "\n")
                            # Clear the old history once accessed
                            history[old_email] = []
                            with open(LICENSE_HISTORY_FILE, "w") as f:
                                json.dump(history, f, indent=2)
            except Exception as e:
                print(f"[!] Warning: Failed to display audit history for previous license: {e}")

        try:
            LICENSE_DIR.mkdir(parents=True, exist_ok=True)
            with open(LICENSE_FILE, "w") as f:
                json.dump({"license_key": key_to_reg.strip(), "licensee": payload}, f, indent=2)
            print(f"[OK] SentryScrub Pro successfully registered to {payload['org']} ({payload['email']}).")
            print(f"[*] License file written to: {LICENSE_FILE}")
            sys.exit(0)
        except Exception as e:
            print(f"[ERROR] Failed to save license file: {e}")
            sys.exit(1)

    print_banner(shell=False)

    if args.command == "help":
        parser.print_help()
        print("\nInteractive Commands (available in --shell or as positional arguments):")
        print("  discover [-i INPUT] [--range RANGE]   Auto-detect columns")
        print("  add -c COL -s STRATEGY                Add a rule to config.yaml")
        print("  remove -c COL                         Remove rule from config.yaml")
        print("  ignore -c HEADER                      Stop discovery from suggesting this header")
        print("  learn -k KEYWORD -s STRATEGY          Teach discovery a new pattern")
        print("  run [-i INPUT] [-o OUTPUT] [--turbo]  Execute the pipeline")
        print("  register                              Register a license key")
        sys.exit(0)

    if args.generate_keys:
        generate_vault_keys()
        sys.exit(0)

    if args.command == "discover" or args.discover:
        run_discovery(args.input, args.range)
        sys.exit(0)

    if args.command == "learn":
        if not args.keyword or not args.strategy:
            print("[ERROR] learn requires -k KEYWORD -s STRATEGY")
            sys.exit(1)
        rules = load_discovery_rules()
        rules['strategies'][args.strategy].append(args.keyword.lower())
        save_discovery_rules(rules)
        print(f"[+] Discovery learned: '{args.keyword}' -> {args.strategy}")
        sys.exit(0)

    if args.command == "ignore":
        if not args.column:
            print("[ERROR] ignore requires -c COLUMN")
            sys.exit(1)
        rules = load_discovery_rules()
        if args.column not in rules['ignored_headers']:
            rules['ignored_headers'].append(args.column)
            save_discovery_rules(rules)
        print(f"[*] Discovery will ignore: '{args.column}'")
        sys.exit(0)

    if args.command == "add":
        if not args.column or not args.strategy:
            print("[ERROR] add requires -c COLUMN -s STRATEGY")
            sys.exit(1)
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f: cfg = yaml.safe_load(f)
        else:
            cfg = {"input_file": args.input, "output_file": "scrubbed.csv", "columns_to_scrub": []}
        
        col_name = resolve_column_name(expand_path(args.input if args.input else cfg.get('input_file')), args.column)
        if col_name:
            cfg.setdefault('columns_to_scrub', []).append({'name': col_name, 'strategy': args.strategy})
            update_yaml_config(cfg)
            print(f"[+] Added: '{col_name}' -> {args.strategy}")
        sys.exit(0)

    if args.command == "remove":
        if not args.column:
            print("[ERROR] remove requires -c COLUMN")
            sys.exit(1)
        if not os.path.exists(CONFIG_FILE):
            print("[ERROR] No config.yaml found.")
            sys.exit(1)
        with open(CONFIG_FILE, "r") as f: cfg = yaml.safe_load(f)
        col_name = resolve_column_name(expand_path(args.input if args.input else cfg.get('input_file')), args.column)
        if col_name:
            cfg['columns_to_scrub'] = [c for c in cfg.get('columns_to_scrub', []) if c['name'] != col_name]
            update_yaml_config(cfg)
            print(f"[-] Removed rule for '{col_name}'.")
        sys.exit(0)

    # Default action: Run the scrub
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f: config = yaml.safe_load(f)
    else:
        config = {"input_file": args.input, "output_file": "scrubbed.csv", "columns_to_scrub": []}
    
    if args.input: config['input_file'] = args.input
    if args.output: config['output_file'] = args.output
    
    if config.get('input_file'):
        execute_scrub(args, config)
    else:
        print("[ERROR] No input file specified. Use -i or configure config.yaml")
        parser.print_usage()


if __name__ == "__main__":
    main()
