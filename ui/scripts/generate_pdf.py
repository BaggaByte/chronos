import subprocess
import sys
from pathlib import Path

ROOT_SCRIPT = Path(__file__).resolve().parent.parent.parent / "scripts" / "generate_pdf.py"
if ROOT_SCRIPT.exists():
    cmd = [sys.executable, str(ROOT_SCRIPT)] + sys.argv[1:]
    sys.exit(subprocess.call(cmd))
else:
    print(f"Could not locate {ROOT_SCRIPT}")
    sys.exit(1)
