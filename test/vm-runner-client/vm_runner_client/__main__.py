import argparse
import sys

from .client import DrakvufVM


parser = argparse.ArgumentParser("CLI client for vm-runner")
parser.add_argument('command', choices=['suspend', 'destroy'])
parser.add_argument('identity', default=None, nargs="?")
args = parser.parse_args()

identity = DrakvufVM.get_vm_identity() or args.identity

if identity is None:
    print("[!] Identity is required outside CI/CD environment", file=sys.stderr)
    sys.exit(1)

print(f"=> {args.command} {identity}", file=sys.stderr)
vm = DrakvufVM(identity)

if args.command == "suspend":
    vm.suspend()
elif args.command == "destroy":
    vm.destroy()
