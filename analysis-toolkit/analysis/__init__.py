"""Analysis toolkit for the PQC-SecOC revision: raw measurement CSVs -> tables, figures, numbers.tex, summary.json."""
import hashlib
import site
import subprocess
import sys
from pathlib import Path

if sys.flags.no_user_site:  # python -I hides the user site-packages, where numpy may be installed
    site.addsitedir(site.getusersitepackages())


def toolkit_commit():
    """Identity of the toolkit code: the git commit of its directory ('-dirty' with uncommitted
    changes there), or, outside a git repository, 'nogit-' plus the first 12 hex digits of the
    SHA-256 over the package's source files."""
    root = Path(__file__).resolve().parent

    def git(*args):
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True).stdout.strip()

    try:
        return git("rev-parse", "--short=12", "HEAD") + ("-dirty" if git("status", "--porcelain", "--", ".") else "")
    except (OSError, subprocess.CalledProcessError):
        digest = hashlib.sha256()
        for path in sorted(root.glob("*.py")):
            digest.update(path.name.encode() + b"\0" + path.read_bytes())
        return "nogit-" + digest.hexdigest()[:12]
