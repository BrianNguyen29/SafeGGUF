#!/usr/bin/env python3
"""
Deterministic Generator for SafeGGUF Security Testbed Fixtures.
Ensures tests/fixtures/security_testbed/* fixtures are deterministically populated.
"""

import sys
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
AST_SCRIPT = REPO_ROOT / "tests" / "advanced_security_testbed.py"

def generate_security_fixtures():
    print("[*] Generating deterministic security testbed fixtures...")
    cmd = [sys.executable, str(AST_SCRIPT), "--generate-only"]
    p = subprocess.run(cmd, check=True)
    return p.returncode

if __name__ == "__main__":
    sys.exit(generate_security_fixtures())
