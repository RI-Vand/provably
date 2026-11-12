"""Console entry points: `provably-mcp` (the MCP server over stdio) and `provably-harden` (the command line tool).
The engine modules sit next to this file when installed (and in the repository root when cloned); they import each other by plain name, so their folder goes on sys.path first."""
import os, sys


def _engine_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return here if os.path.exists(os.path.join(here, "mcp_server.py")) else os.path.dirname(here)       # installed wheel / repository checkout


def main():
    sys.dont_write_bytecode = True
    sys.path.insert(0, _engine_dir())
    import mcp_server
    mcp_server.main()


def harden_main():
    sys.dont_write_bytecode = True
    sys.path.insert(0, _engine_dir())
    import harden_core
    sys.exit(harden_core.main())


if __name__ == "__main__":
    main()
