"""
Drakvuf-Sandbox shell utility for easy managing and debugging Drakvuf instance
"""
from .install import install
from .main import main

main.add_command(install)
