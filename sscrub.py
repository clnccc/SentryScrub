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
import polars as pl
from pathlib import Path
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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

def load_vault_material():
    if not os.path.exists(KEY_FILE):
        print(f"[ERROR] Keys missing. Run: --generate-keys")
        return None, None
    with open(KEY_FILE, "rb") as f: m_key = bytearray(f.read())
    with open(SALT_FILE, "rb") as f: m_salt = bytearray(f.read())
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
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(str(val).encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

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
        idx = int(col_ref) - 1 if col_ref.isdigit() else excel_col_to_index(col_ref)
        if 0 <= idx < len(headers): return headers[idx]
        print(f"[ERROR] Column index {idx+1} out of bounds.")
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
    m_key, m_salt = load_vault_material()
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
        print(f"[*] Time: {elapsed:.2f} seconds.")
        generate_audit_log(config, row_count, elapsed_time=elapsed)
    except Exception as e: print(f"\n[FATAL ERROR] Pipeline stalled: {str(e)}")
    finally:
        secure_mem_wipe(m_key); secure_mem_wipe(m_salt); gc.collect()

# --- SHELL MODE ---

def run_shell(parser):
    print("\n🛡️ sscrub Interactive Shell v1.0")
    print("Type 'help' for commands, 'run' to execute, or 'exit' to quit.\n")
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
    parser.add_argument("--shell", action="store_true", help="Enter interactive mode")
    parser.add_argument("command", nargs="?", choices=["add", "remove", "ignore", "learn", "exit", "help", "run"], help="Optional command to execute")
    parser.add_argument("-c", "--column", help="Target column for add/remove/ignore")
    parser.add_argument("-s", "--strategy", choices=["MASK", "HASH", "ENCRYPT"], help="Strategy for add/learn")

    # If no arguments or --shell, enter interactive mode
    if len(sys.argv) == 1 or "--shell" in sys.argv:
        run_shell(parser)
        sys.exit(0)

    args = parser.parse_args()

    if args.command == "help":
        parser.print_help()
        print("\nInteractive Commands (available in --shell or as positional arguments):")
        print("  discover [-i INPUT] [--range RANGE]   Auto-detect columns")
        print("  add -c COL -s STRATEGY                Add a rule to config.yaml")
        print("  remove -c COL                         Remove rule from config.yaml")
        print("  ignore -c HEADER                      Stop discovery from suggesting this header")
        print("  learn -k KEYWORD -s STRATEGY          Teach discovery a new pattern")
        print("  run [-i INPUT] [-o OUTPUT] [--turbo]  Execute the pipeline")
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
