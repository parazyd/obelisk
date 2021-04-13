#!/usr/bin/env python3
# Run this from the repo root to format the python codebase.
# Depends:
# black - https://github.com/psf/black
# yapf  - https://github.com/google/yapf
from subprocess import run
run(["black", "-l", "80", "."])
run(["yapf", "-i", "-r", "."])
