"""
Drakvuf-Sandbox shell utility for easy managing and debugging Drakvuf instance
"""
from .main import main
from .install import install

main.add_command(install)
