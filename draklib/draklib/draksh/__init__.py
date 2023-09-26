"""
Drakvuf-Sandbox shell utility for easy managing and debugging Drakvuf instance
"""
from .install import install
from .main import main
from .postinstall import postinstall
from .run import run

main.add_command(install)
main.add_command(postinstall)
main.add_command(run)

