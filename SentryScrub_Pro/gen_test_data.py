#!/usr/bin/env python3
"""
gen_test_data.py
Generates fake B2B/employee CSV datasets using the Faker library for SentryScrub testing.
"""

import csv
import sys
from pathlib import Path
from faker import Faker

def generate_csv(file_path, num_rows):
    print(f"[*] Generating {num_rows:,} rows into {file_path.name}...")
    fake = Faker()
    
    headers = ["id", "name", "email", "ssn", "company", "phone", "salary"]
    
    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for i in range(1, num_rows + 1):
            writer.writerow([
                i,
                fake.name(),
                fake.email(),
                fake.ssn(),
                fake.company(),
                fake.phone_number(),
                fake.random_int(40000, 150000)
            ])
    print(f"[OK] Saved {file_path.name}.")

def main():
    root_dir = Path("/home/clara/SentryScrub_Pro")
    
    # Generate 100 rows (under-limit)
    generate_csv(root_dir / "small_faker_data.csv", 100)
    
    # Generate 60,000 rows (over-limit)
    generate_csv(root_dir / "large_faker_data.csv", 60000)
    
    print("\n[SUCCESS] Fake datasets generated successfully in SentryScrub_Pro directory!")

if __name__ == "__main__":
    main()
