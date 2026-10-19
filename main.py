#!/usr/bin/env python3
"""
main.py - QSecure 2.0 Root Launcher Entry Point
================================================
Forwards execution to Main_File_Nest/main.py ensuring seamless launching
whether invoked from repository root or from within Main_File_Nest.
"""

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
NEST_DIR = ROOT_DIR / "Main_File_Nest"

# Add Main_File_Nest to sys.path and switch working directory context if needed
if str(NEST_DIR) not in sys.path:
    sys.path.insert(0, str(NEST_DIR))

os.chdir(NEST_DIR)

from main import main

if __name__ == "__main__":
    main()
