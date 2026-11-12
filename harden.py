#!/usr/bin/env python3
"""Command line entry point: python3 harden.py app.py   (the engine is in harden_core.py)"""
import sys
sys.dont_write_bytecode = True
from harden_core import harden_source, summary, collect, harden_web_project, main   # noqa: F401

if __name__ == "__main__":
    sys.exit(main())
