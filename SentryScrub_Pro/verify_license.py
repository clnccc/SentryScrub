#!/usr/bin/env python3
"""
verify_license.py
Validation script to test the SentryScrub offline licensing system.
"""

import sys
import os
import shutil
import subprocess
import json
import csv
from pathlib import Path

# Paths
VENV_PYTHON = "/home/clara/SentryScrub_Pro/.sentry_venv/bin/python3"
SSCRUB_PY = "/home/clara/SentryScrub_Pro/sscrub.py"
GEN_LICENSE_PY = "/home/clara/SentryScrub_Pro/generate_license.py"
TEST_DIR = Path("/home/clara/SentryScrub_Pro/temp_test")
GLOBAL_LICENSE_FILE = Path(os.path.expanduser("~/.config/sscrub/license.json"))

# Test files
DATA_10_ROWS = TEST_DIR / "data_10.csv"
DATA_60K_ROWS = TEST_DIR / "data_60k.csv"
OUTPUT_FILE = TEST_DIR / "scrubbed.csv"
CONFIG_FILE = TEST_DIR / "config.yaml"

def setup_environment():
    """Deterministic state setup."""
    print("[*] Setting up test environment...")
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR)
    TEST_DIR.mkdir(parents=True, exist_ok=True)
    
    # Generate dummy test keys
    with open(TEST_DIR / "master.key", "wb") as f:
        f.write(os.urandom(32))
    with open(TEST_DIR / "hash.salt", "wb") as f:
        f.write(os.urandom(16))
        
    # Copy persistent private key to test directory for matching signatures
    root_private_key = Path("/home/clara/SentryScrub_Pro/license_private.key")
    if root_private_key.exists():
        shutil.copy(root_private_key, TEST_DIR / "license_private.key")
    
    # Temporarily hide existing global license file
    if GLOBAL_LICENSE_FILE.exists():
        backup_path = GLOBAL_LICENSE_FILE.with_suffix(".json.bak")
        if backup_path.exists():
            os.remove(backup_path)
        GLOBAL_LICENSE_FILE.rename(backup_path)
        
    # Generate test CSVs
    # 10 rows
    with open(DATA_10_ROWS, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "name", "email", "ssn"])
        for i in range(10):
            writer.writerow([i, f"Name {i}", f"user{i}@test.com", f"123-45-{i:04d}"])

    # 60,000 rows
    with open(DATA_60K_ROWS, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "name", "email", "ssn"])
        for i in range(60000):
            writer.writerow([i, f"Name {i}", f"user{i}@test.com", f"123-45-{i:04d}"])

    # Create dummy config.yaml in TEST_DIR
    config = {
        "input_file": str(DATA_10_ROWS),
        "output_file": str(OUTPUT_FILE),
        "columns_to_scrub": [
            {"name": "name", "strategy": "MASK"},
            {"name": "email", "strategy": "HASH"},
            {"name": "ssn", "strategy": "ENCRYPT"}
        ]
    }
    with open(TEST_DIR / "config.yaml", "w") as f:
        import yaml
        yaml.dump(config, f)

def restore_environment():
    """Restore original system state."""
    print("[*] Restoring environment...")
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR)
        
    # Remove any test-generated global license
    if GLOBAL_LICENSE_FILE.exists():
        os.remove(GLOBAL_LICENSE_FILE)
        
    # Remove test-generated session and history logs
    history_file_path = GLOBAL_LICENSE_FILE.parent / "license_history.json"
    if history_file_path.exists():
        os.remove(history_file_path)
    session_file_path = GLOBAL_LICENSE_FILE.parent / "session_files.json"
    if session_file_path.exists():
        os.remove(session_file_path)

    # Restore original global license backup
    backup_path = GLOBAL_LICENSE_FILE.with_suffix(".json.bak")
    if backup_path.exists():
        backup_path.rename(GLOBAL_LICENSE_FILE)
    print("[OK] Original license state restored.")

def run_cmd(args, stdin_input=None):
    res = subprocess.run(
        args,
        input=stdin_input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(TEST_DIR)
    )
    return res.returncode, res.stdout, res.stderr

def run_tests():
    # 1. Test 10 rows in Community Edition (Unlicensed)
    print("\n--- Test 1: Community Edition - 10 Rows (Under Limit) ---")
    ret, out, err = run_cmd([VENV_PYTHON, SSCRUB_PY, "--force"])
    print(out)
    if "Community Edition" not in out:
        raise AssertionError("Failed: Should run in Community Edition")
    if "SUCCESS: Data saved to" not in out:
        raise AssertionError("Failed: Under 50,000 rows should succeed in Community Edition")
    print("[PASS] Test 1: Under limit succeeds in Community Mode.")

    # 2. Test 60k rows in Community Edition (Should hit Limit Error)
    print("\n--- Test 2: Community Edition - 60,000 Rows (Over Limit) ---")
    # Update config.yaml to use 60k rows
    with open(TEST_DIR / "config.yaml", "r") as f:
        import yaml
        cfg = yaml.safe_load(f)
    cfg["input_file"] = str(DATA_60K_ROWS)
    with open(TEST_DIR / "config.yaml", "w") as f:
        yaml.dump(cfg, f)

    ret, out, err = run_cmd([VENV_PYTHON, SSCRUB_PY, "--force"])
    print(out)
    if "[LIMIT ERROR]" not in out:
        raise AssertionError("Failed: Over 50,000 rows should trigger Limit Error in Community Edition")
    print("[PASS] Test 2: Limit error is properly enforced.")

    # 3. Generate a valid license key
    print("\n--- Test 3: Generating Valid License ---")
    ret, out, err = run_cmd([VENV_PYTHON, GEN_LICENSE_PY, "--email", "test@verify.com", "--org", "Verification Corp", "--keep-record", "n"])
    if ret != 0:
        raise AssertionError(f"Failed to generate license: {err}")
        
    # Extract license key from stdout
    key_lines = []
    capture = False
    for line in out.splitlines():
        if "Paste the following license key in the CLI:" in line:
            capture = True
            continue
        if capture:
            if line.startswith("-"):
                break
            key_lines.append(line.strip())
    license_key = "".join(key_lines).strip()
    if not license_key:
        raise AssertionError("Failed to parse generated license key")
    print(f"[OK] Generated License Key: {license_key[:30]}...")

    # 4. Register license key
    print("\n--- Test 4: Registering Valid License ---")
    ret, out, err = run_cmd([VENV_PYTHON, SSCRUB_PY, "--register", license_key])
    print(out)
    if ret != 0 or "[OK] SentryScrub Pro successfully registered" not in out:
        raise AssertionError(f"Failed to register valid license: {err}")
    if not GLOBAL_LICENSE_FILE.exists():
        raise AssertionError("License file was not written to global destination")
    print("[PASS] Test 4: Valid license successfully registered.")

    # 5. Run 60k rows again with Pro License (Should succeed)
    print("\n--- Test 5: Pro Edition - 60,000 Rows (Should Succeed) ---")
    ret, out, err = run_cmd([VENV_PYTHON, SSCRUB_PY, "--force"])
    print(out)
    if "Pro Edition" not in out:
        raise AssertionError("Failed: Should run in Pro Edition")
    if "SUCCESS: Data saved to" not in out:
        raise AssertionError("Failed: Row limit was not bypassed in Pro Edition")
    print("[PASS] Test 5: Row limit is successfully lifted in Pro Mode.")

    # 6. Test registering an invalid/tampered license key
    print("\n--- Test 6: Registering Invalid/Tampered License ---")
    tampered_key = license_key + "X"
    ret, out, err = run_cmd([VENV_PYTHON, SSCRUB_PY, "--register", tampered_key])
    print(out)
    if ret == 0 or "[ERROR] Invalid license key signature" not in out:
        raise AssertionError("Failed: Tampered license key signature should be rejected")
    print("[PASS] Test 6: Invalid/Tampered signatures are correctly rejected.")

    # 7. Test Session-based file tracking and exit clearing
    print("\n--- Test 7: Session-based File Tracking and Exit Clearing ---")
    sys.path.insert(0, "/home/clara/SentryScrub_Pro")
    import sscrub
    
    # Ensure starting clean
    if sscrub.SESSION_FILES_LOG.exists():
        os.remove(sscrub.SESSION_FILES_LOG)
        
    # Test Community Edition log
    sscrub.IS_PRO_EDITION = False
    sscrub.log_session_file(Path("/dummy/path/community_file.csv"))
    
    with open(sscrub.SESSION_FILES_LOG, "r") as f:
        session_data = json.load(f)
    if "Community Edition" not in session_data or len(session_data["Community Edition"]) != 1:
        raise AssertionError("Failed: Community file not logged correctly")
    if session_data["Community Edition"][0] != "/dummy/path/community_file.csv":
        raise AssertionError("Failed: Incorrect community file path logged")
        
    # Test Pro Edition log
    sscrub.IS_PRO_EDITION = True
    sscrub.LICENSE_INFO = {"email": "test@verify.com", "org": "Verification Corp"}
    sscrub.log_session_file(Path("/dummy/path/pro_file.csv"))
    
    with open(sscrub.SESSION_FILES_LOG, "r") as f:
        session_data = json.load(f)
    if "test@verify.com" not in session_data or len(session_data["test@verify.com"]) != 1:
        raise AssertionError("Failed: Pro file not logged correctly under license email")
    if session_data["test@verify.com"][0] != "/dummy/path/pro_file.csv":
        raise AssertionError("Failed: Incorrect pro file path logged")
        
    # Test clear_session_files
    sscrub.clear_session_files()
    with open(sscrub.SESSION_FILES_LOG, "r") as f:
        session_data = json.load(f)
    if session_data != {}:
        raise AssertionError("Failed: Session files log was not cleared/emptied")
        
    # Clean up test log file
    if sscrub.SESSION_FILES_LOG.exists():
        os.remove(sscrub.SESSION_FILES_LOG)
        
    print("[PASS] Test 7: Session file tracking and clearing verified.")

    # 8. Test Persistent history tracking and secure audit rotation
    print("\n--- Test 8: Persistent History Tracking and Secure Audit Rotation ---")
    
    # Generate a license with --keep-record y
    ret, out, err = run_cmd([VENV_PYTHON, GEN_LICENSE_PY, "--email", "audit@verify.com", "--org", "Audit Corp", "--keep-record", "y"])
    if ret != 0:
        raise AssertionError("Failed to generate license with keep-record")
        
    # Extract key
    key_lines = []
    capture = False
    for line in out.splitlines():
        if "Paste the following license key in the CLI:" in line:
            capture = True
            continue
        if capture:
            if line.startswith("-"):
                break
            key_lines.append(line.strip())
    audit_license_key = "".join(key_lines).strip()
    
    # Register the audit license key
    ret, out, err = run_cmd([VENV_PYTHON, SSCRUB_PY, "--register", audit_license_key])
    if ret != 0 or "[OK] SentryScrub Pro successfully registered" not in out:
        raise AssertionError("Failed to register audit license")
        
    # Run a pipeline execution to generate a file path log in history
    with open(TEST_DIR / "config.yaml", "r") as f:
        import yaml
        cfg = yaml.safe_load(f)
    cfg["input_file"] = str(DATA_10_ROWS)
    cfg["output_file"] = str(TEST_DIR / "audit_output.csv")
    with open(TEST_DIR / "config.yaml", "w") as f:
        yaml.dump(cfg, f)
        
    # Run pipeline
    ret, out, err = run_cmd([VENV_PYTHON, SSCRUB_PY, "--force"])
    if ret != 0 or "SUCCESS: Data saved to" not in out:
        raise AssertionError("Pipeline execution failed under audit license")
        
    # Verify the file is in license_history.json
    history_file_path = GLOBAL_LICENSE_FILE.parent / "license_history.json"
    if not history_file_path.exists():
        raise AssertionError("license_history.json was not created")
    with open(history_file_path, "r") as f:
        history_data = json.load(f)
    if "audit@verify.com" not in history_data or len(history_data["audit@verify.com"]) != 1:
        raise AssertionError("Exported file was not persistently logged under audit license")
        
    # Generate another license to trigger change/registration
    ret, out, err = run_cmd([VENV_PYTHON, GEN_LICENSE_PY, "--email", "new@verify.com", "--org", "New Corp", "--keep-record", "n"])
    key_lines = []
    capture = False
    for line in out.splitlines():
        if "Paste the following license key in the CLI:" in line:
            capture = True
            continue
        if capture:
            if line.startswith("-"):
                break
            key_lines.append(line.strip())
    new_license_key = "".join(key_lines).strip()
    
    # Register new license. This should print the previous audit history and clear it.
    ret, out, err = run_cmd([VENV_PYTHON, SSCRUB_PY, "--register", new_license_key])
    print(out)
    if "[SECURITY AUDIT] Export History for Previous License" not in out:
        raise AssertionError("Failed: Previous export history was not displayed upon license change")
    if "audit_output.csv" not in out:
        raise AssertionError("Failed: Exported file path was missing from displayed security audit")
        
    # Verify the old history has been cleared/emptied in the file
    with open(history_file_path, "r") as f:
        history_data = json.load(f)
    if history_data.get("audit@verify.com") != []:
        raise AssertionError("Failed: Audit history for the old license was not cleared after access")
        
    print("[PASS] Test 8: Persistent history tracking and secure audit rotation verified.")

def main():
    try:
        setup_environment()
        run_tests()
        print("\n" + "="*40)
        print("🎉 ALL LICENSING VALIDATION TESTS PASSED!")
        print("="*40)
    except Exception as e:
        print(f"\n[TEST FAILED] {e}")
        sys.exit(1)
    finally:
        restore_environment()

if __name__ == "__main__":
    main()
