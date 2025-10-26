import os
import sys
import runpy

# Ensure `src` directory is on sys.path so `import core` works
ROOT = os.path.dirname(__file__)
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

# Delegate to the module entrypoint
if __name__ == "__main__":
    # runpy will execute src.main as if it were run with -m
    runpy.run_module("src.main", run_name="__main__")
