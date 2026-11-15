#!/usr/bin/env python3
"""Bundle the ctfkit package into a single portable `ctfkit.pyz` (zipapp).

The .pyz is one self-contained file you can scp onto any box with Python 3
and run directly:

    python3 ctfkit.pyz triage ./chall
    ./ctfkit.pyz triage ./chall          # on Linux (executable bit + shebang)

Usage:
    python3 build.py
"""
import pathlib
import shutil
import stat
import zipapp

ROOT = pathlib.Path(__file__).resolve().parent
STAGE = ROOT / ".build_stage"
OUT = ROOT / "ctfkit.pyz"


def main():
    if STAGE.exists():
        shutil.rmtree(STAGE)
    STAGE.mkdir()
    shutil.copytree(
        ROOT / "ctfkit", STAGE / "ctfkit",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    zipapp.create_archive(
        STAGE,
        target=OUT,
        interpreter="/usr/bin/env python3",
        main="ctfkit.cli:main",
    )
    shutil.rmtree(STAGE)
    # make it directly executable on POSIX
    try:
        OUT.chmod(OUT.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass
    print(f"built {OUT.name}  ({OUT.stat().st_size} bytes)")
    print(f"run:  python3 {OUT.name} triage ./chall")


if __name__ == "__main__":
    main()
