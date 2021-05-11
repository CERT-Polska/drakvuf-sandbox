#! /usr/bin/env python3
# bump_version.py 0.1.0
import difflib
import json
import re
import sys
from pathlib import Path

CONFIG = json.loads((Path(__file__).parent / "bump_version.json").read_text())
CURRENT_DIR = Path.cwd()
VERSION_FILES = {
    (CURRENT_DIR / path): pattern for path, pattern in CONFIG["files"].items()
}
VERSION_REGEX = CONFIG["regex"]


def main(new_version):
    input_files = {}
    output_files = {}
    old_version = None

    if not re.match(fr"^{VERSION_REGEX}$", new_version):
        print(f"[!] '{new_version}' doesn't match the regex: {VERSION_REGEX}")
        return

    def subst_version(repl):
        return (
            repl.string[repl.start(0) : repl.start(1)]
            + new_version
            + repl.string[repl.end(1) : repl.end(0)]
        )

    for path in VERSION_FILES.keys():
        if not path.exists():
            print(f"[!] File {str(path)} is missing. Are you in project root dir?")
            return False

        with open(path, "r") as f:
            content = input_files[path] = f.read()

        pattern = VERSION_FILES[path].replace("$VERSION", VERSION_REGEX)
        print(pattern)
        version = next(re.finditer(pattern, content)).group(1)
        output_files[path] = re.sub(pattern, subst_version, content, count=1)

        if old_version is not None and version != old_version:
            print(
                f"[!] {str(path)} contains different version than other files "
                f"({version} != {old_version})"
            )
        old_version = version

    for path in VERSION_FILES.keys():
        input_lines = input_files[path].splitlines()
        output_lines = output_files[path].splitlines()
        if input_lines == output_lines:
            print("[*] No changes detected.")
            return
        print("=== " + str(path))
        for line in difflib.unified_diff(input_lines, output_lines, lineterm=""):
            print(line)

    response = ""
    while response.lower() not in {"y", "n", "yes", "no"}:
        response = input("[*] Check above diff ^ Is it correct? (y/n): ")

    if response.lower() in {"y", "yes"}:
        for path, content in output_files.items():
            with open(path, "w") as f:
                f.write(content)
        print("[+] Changes applied!")
    else:
        print("[-] Changes discarded.")


if __name__ == "__main__":
    if not sys.argv[1:]:
        print("Usage: bump_version.py [new_version]")
    else:
        main(sys.argv[1])
