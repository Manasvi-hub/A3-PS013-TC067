import os
import sys
import subprocess
import stat
import glob
import csv
from pathlib import Path

def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace')

def check_1():
    print("Check 1: pytest ... ", end="")
    res = run_cmd("python -m pytest -q")
    if res.returncode == 0 and "failed" not in res.stdout and "skipped" not in res.stdout:
        print("PASS")
        return True
    print("FAIL")
    return False

def check_2():
    print("Check 2: ruff ... ", end="")
    res = run_cmd("python -m ruff check src tests")
    if res.returncode == 0:
        print("PASS")
        return True
    print("FAIL")
    return False

def check_3():
    print("Check 3: forensic --help ... ", end="")
    res = run_cmd("forensic --help")
    expected = ["ingest", "verify", "build", "skew", "search", "report", "ui", "run-all"]
    if res.returncode == 0 and all(cmd in res.stdout for cmd in expected):
        print("PASS")
        return True
    print("FAIL")
    return False

def check_4():
    print("Check 4: forensic run-all ... ", end="")
    res = run_cmd("forensic run-all")
    if res.returncode != 0:
        print("FAIL (exit non-zero)")
        return False
    
    out = res.stdout + res.stderr
    if "anchor_median" not in out:
        print("FAIL (missing anchor_median)")
        return False
    
    # Check for gaps numbers
    if not all(str(n) in out for n in [0, 4, 5]):
        print("FAIL (missing 4, 5, or 0)")
        return False
        
    print("PASS")
    return True

def check_5():
    print("Check 5: Tamper test ... ", end="")
    target_dir = Path("cases/s3_clock_skew/evidence")
    if not target_dir.exists():
        print("FAIL (no evidence dir)")
        return False
    
    files = [f for f in target_dir.iterdir() if f.is_file()]
    if not files:
        print("FAIL (no files)")
        return False
    
    target_file = files[0]
    
    # Make writable
    target_file.chmod(target_file.stat().st_mode | stat.S_IWRITE)
    # Append byte
    with open(target_file, "ab") as f:
        f.write(b"X")
    
    res = run_cmd("forensic verify --case cases/s3_clock_skew")
    if res.returncode != 1 or "TAMPERED" not in (res.stdout + res.stderr):
        print("FAIL")
        run_cmd("forensic run-all") # restore
        return False
    
    run_cmd("forensic run-all") # restore
    print("PASS")
    return True

def check_6():
    print("Check 6: UNKNOWN and <<<<<<< ... ", end="")
    for report_file in glob.glob("reports/*.html"):
        try:
            with open(report_file, "r", encoding="utf-8", errors="replace") as f:
                if "UNKNOWN" in f.read():
                    print("FAIL (UNKNOWN found)")
                    return False
        except Exception:
            pass
            
    res = run_cmd('git grep "<<<<<<<"')
    if res.returncode == 0:
        print("FAIL (<<<<<<< found)")
        return False
        
    print("PASS")
    return True

def check_7():
    print("Check 7: Git hygiene ... ", end="")
    res = run_cmd("git ls-files")
    files = res.stdout.splitlines()
    forbidden = ["egg-info", "cases/", "reports/", "__pycache__", "mock_s3_db.py"]
    for f in files:
        for bad in forbidden:
            if bad in f.replace("\\", "/"):
                print(f"FAIL ({bad} found in {f})")
                return False
                
    print("PASS")
    return True

def check_8():
    print("Check 8: Required files ... ", end="")
    reqs = [
        "README.md",
        "docs/pseudocode.md",
        "docs/demo_script.md",
        "evaluation/triage_summary.md",
        "evaluation/parsing_gap_analysis.md"
    ]
    failed = False
    for r in reqs:
        if not Path(r).exists():
            print(f"\nFAIL: {r} missing")
            failed = True
    
    if not (Path("A3-PS013-TC067.pdf").exists() or Path("docs/A3-PS013-TC067.pdf").exists()):
        print("\nFAIL: A3-PS013-TC067.pdf missing")
        failed = True
        
    if failed:
        return False
        
    print("PASS")
    return True

def check_9():
    print("Check 9: Triage results ... ", end="")
    csv_path = Path("evaluation/triage_results.csv")
    if not csv_path.exists():
        print("FAIL (missing)")
        return False
        
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = list(csv.reader(f))
            if len(reader) < 18:
                print("FAIL (too few rows)")
                return False
            for row in reader:
                if any("Used grep and sort" in str(cell) for cell in row):
                    print("FAIL (Used grep and sort found)")
                    return False
    except Exception:
        print("FAIL (read error)")
        return False
        
    print("PASS")
    return True

def main():
    checks = [
        check_1, check_2, check_3, check_4, check_5,
        check_6, check_7, check_8, check_9
    ]
    
    passed = 0
    failed = 0
    
    for check_fn in checks:
        if check_fn():
            passed += 1
        else:
            failed += 1
            
    print(f"\n{passed} passed, {failed} failed")
    if failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
