#!/usr/bin/env python3
"""
NocturneRecon - State-of-the-art API-free OSINT & Passive Recon Framework
Author: Muzan Sano
License: MIT
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.cli import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)
