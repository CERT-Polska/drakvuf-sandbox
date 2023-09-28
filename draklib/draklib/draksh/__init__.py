"""
Drakvuf-Sandbox shell utility for easy managing and debugging Drakvuf instance
"""
from .install import install
from .main import main
from .postinstall import postinstall
from .run import run
from .vm_destroy import vm_destroy
from .vm_restore import vm_restore

main.add_command(install)
main.add_command(postinstall)
main.add_command(run)
main.add_command(vm_destroy)
main.add_command(vm_restore)
