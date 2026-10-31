import os
import sys
from pathlib import Path

# Ensure TESTING environment flag is set before any modules are loaded
os.environ.setdefault("TESTING", "1")

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
