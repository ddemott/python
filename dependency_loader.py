import importlib
import subprocess
import sys

class DependencyLoader:
    @staticmethod
    def load_dependencies():
        required = [
            "PySide6",
            # Add other dependencies here if needed
        ]
        for pkg in required:
            try:
                importlib.import_module(pkg)
            except ImportError:
                subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])