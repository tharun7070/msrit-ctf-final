#!/usr/bin/env python3
"""FLAG THEFT AUTO — CTFd Challenge Importer Wrapper
Imports all 15 validated challenges into a running CTFd instance.

Usage:
  # Dry-run validation (no changes made):
  python scripts/import_challenges.py

  # Apply changes to local CTFd:
  $env:CTFD_TOKEN = "your_ctfd_admin_token"
  python scripts/import_challenges.py --apply --url http://localhost:8000 --allow-http
"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
IMPORTER_PATH = PROJECT_ROOT / "organizer_private" / "CTFD_IMPORT" / "import_ctfd.py"

if not IMPORTER_PATH.is_file():
    print(f"Error: Importer not found at {IMPORTER_PATH}", file=sys.stderr)
    sys.exit(1)

# Add organizer CTFD_IMPORT directory to sys.path and execute
sys.path.insert(0, str(IMPORTER_PATH.parent))
import import_ctfd

if __name__ == "__main__":
    import_ctfd.main()
