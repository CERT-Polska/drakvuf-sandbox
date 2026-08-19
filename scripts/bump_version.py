#! /usr/bin/env python3
# Copyright (c) 2026, CERT Polska. All rights reserved.
#
# This file's content is free software; you can redistribute and/or
# modify it under the terms of the *BSD 3-Clause "New" or "Revised"
#
# bump_version 0.2.0 - Utility for version bump and management
#
# This file automates the version bumping in various files and
# assists CI workflow in determining the version information.
#
# Usage: python3 bump_version.py --help

import argparse
import difflib
import itertools
import tomllib
import re
import sys

from pathlib import Path

SCRIPT_ROOT = Path(__file__).parent
PROJECT_ROOT = SCRIPT_ROOT.parent

CONFIG = tomllib.loads((SCRIPT_ROOT / "bump_version.toml").read_text())
VERSION_FILES = {
    (PROJECT_ROOT / path): patterns for path, patterns in CONFIG["files"].items()
}
# https://packaging.python.org/en/latest/specifications/version-specifiers/#version-specifiers
VERSION_REGEX = (
    r"(?P<version>"
    r"(?P<major>\d+)[.]"
    r"(?P<minor>\d+)[.]"
    r"(?P<patch>\d+)"
    r"(?P<pre_release>(?:a|b|rc)\d+)?"
    r"(?P<post_release>(?:.post)\d+)?"
    r"(?P<dev_release>(?:.dev)\d+)?"
    r")"
)
CHANGELOG_FILE = PROJECT_ROOT / "CHANGELOG.md"


def get_changelog_header_pattern() -> str:
    """Load and validate changelog header from configuration"""
    header_pattern = CONFIG.get("changelog", {}).get("header_pattern")

    if not header_pattern:
        raise RuntimeError(
            "[changelog].header_pattern is undefined in bump_version.toml"
        )

    if not "$VERSION" in header_pattern:
        raise RuntimeError("[changelog].header_pattern must have $VERSION mark")

    return header_pattern


def load_changelog() -> str:
    """Load changelog file contents"""
    if not CHANGELOG_FILE.exists():
        raise RuntimeError(f"Changelog file '{CHANGELOG_FILE}' doesn't exist")

    return CHANGELOG_FILE.read_text()


def extract_changelog() -> dict[str, str]:
    """Load changelog entries for each version"""
    changelog = load_changelog()
    header_pattern = get_changelog_header_pattern()

    version_pattern = header_pattern.replace("$VERSION", VERSION_REGEX)
    matches = re.finditer(version_pattern, changelog)
    entries = {}
    for cur_version, next_version in itertools.pairwise(
        itertools.chain(matches, [None])
    ):
        start = changelog.index("\n", cur_version.end())
        end = (
            len(changelog)
            if not next_version
            else changelog.rindex("\n", start, next_version.start())
        )
        entries[cur_version.group("version")] = changelog[start:end].strip()
    return entries


def find_latest_version() -> str:
    """Find current latest version from version files"""
    current_version = None

    for path in VERSION_FILES.keys():
        if not path.exists():
            raise RuntimeError(f"File {path} is missing in project root dir?")

        content = path.read_text()

        for pattern in VERSION_FILES[path]:
            pattern = pattern.replace("$VERSION", VERSION_REGEX)
            version = next(re.finditer(pattern, content)).group("version")
            if current_version is not None and version != current_version:
                raise RuntimeError(
                    f"{path} contains different version than other files "
                    f"({version} != {current_version})"
                )
            current_version = version
    if not current_version:
        raise RuntimeError("Version files not found or undefined")
    return current_version


def increment_version(version: str, major: bool, minor: bool, patch: bool) -> str:
    """
    Increment version number.

    Raises RuntimeError when version is a pre-release or dev-release.
    Major, minor and patch flags are treated as mutually exclusive.

    :param version: Version number to increment
    :param major: Increment major
    :param minor: Increment minor
    :param patch: Increment patch
    :return: Incremented version number
    """
    version_match = re.fullmatch(VERSION_REGEX, version)
    if not version_match:
        raise RuntimeError(f"'{version}' doesn't match the regex: {VERSION_REGEX}")
    if version_match.group("pre_release") or version_match.group("dev_release"):
        raise RuntimeError(
            f"'{version}' is a pre-release version, please provide version manually"
        )

    vmajor = int(version_match.group("major"))
    vminor = int(version_match.group("minor"))
    vpatch = int(version_match.group("patch"))
    if major:
        vmajor = vmajor + 1
        vminor = vpatch = 0
    elif minor:
        vminor = vminor + 1
        vpatch = 0
    elif patch:
        vpatch = vpatch + 1
    return f"{vmajor}.{vminor}.{vpatch}"


def bump_version(new_version: str) -> None:
    """
    Interactively bumps version, prompting user for confirmation

    :param new_version: New version specified by user
    """
    input_files = {}
    output_files = {}
    old_version = None

    if not re.fullmatch(VERSION_REGEX, new_version):
        raise RuntimeError(f"'{new_version}' doesn't match the regex: {VERSION_REGEX}")

    def subst_version(repl):
        return (
            repl.string[repl.start(0) : repl.start(1)]
            + new_version
            + repl.string[repl.end(1) : repl.end(0)]
        )

    for path in VERSION_FILES.keys():
        if not path.exists():
            raise RuntimeError(f"File {path} is missing in project root dir?")

        content = input_files[path] = path.read_text()

        for pattern in VERSION_FILES[path]:
            pattern = pattern.replace("$VERSION", VERSION_REGEX)
            version = next(re.finditer(pattern, content)).group("version")
            content = re.sub(pattern, subst_version, content)
            output_files[path] = content

            if old_version is not None and version != old_version:
                raise RuntimeError(
                    f"{path} contains different version than other files "
                    f"({version} != {old_version})"
                )
            old_version = version

    if CHANGELOG_FILE.exists():
        changelog = load_changelog()
        header_pattern = get_changelog_header_pattern()
        changelog_entries = extract_changelog()
        if new_version not in changelog_entries:
            if "new_header_pattern" in CONFIG.get("changelog", {}):
                version_header = CONFIG["changelog"]["new_header_pattern"].replace(
                    "$VERSION", new_version
                )
            else:
                version_header = header_pattern.replace("$VERSION", new_version)
            input_files[CHANGELOG_FILE] = changelog
            output_files[CHANGELOG_FILE] = (
                changelog.rstrip() + "\n\n" + version_header + "\n\n"
            )

    changes = False

    for path in output_files.keys():
        input_lines = input_files[path].splitlines()
        output_lines = output_files[path].splitlines()
        if input_lines == output_lines:
            continue
        changes = True
        print("=== " + str(path))
        for line in difflib.unified_diff(input_lines, output_lines, lineterm=""):
            print(line)

    if not changes:
        print("[*] No changes detected.")
        return

    response = ""
    while response.lower() not in {"y", "n", "yes", "no"}:
        response = input("[*] Check above diff ^ Is it correct? (y/n): ")

    if response.lower() in {"y", "yes"}:
        for path, content in output_files.items():
            with open(path, "w") as f:
                f.write(content)
        print("[+] Changes applied!")
        if CHANGELOG_FILE in output_files:
            print(
                "[+] New changelog entry was created. Make sure to fill it before applying version bump."
            )
    else:
        print("[-] Changes discarded.")


def parse_args(args: tuple[str, ...]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=Path(__file__).name)
    subparsers = parser.add_subparsers(dest="command")

    bump = subparsers.add_parser("bump", help="bump the project version")
    group = bump.add_mutually_exclusive_group(required=True)
    group.add_argument("--major", action="store_true", help="bump the major version")
    group.add_argument("--minor", action="store_true", help="bump the minor version")
    group.add_argument("--patch", action="store_true", help="bump the patch version")
    group.add_argument(
        "version", nargs="?", default=None, help="set an explicit version"
    )

    subparsers.add_parser("version", help="print the current version")

    changelog = subparsers.add_parser("changelog", help="print the changelog")
    changelog.add_argument(
        "version", nargs="?", default=None, help="version to show (default: latest)"
    )

    if not len(args) or args[0] not in [*subparsers.choices, "-h", "--help"]:
        args = "bump", *args
    return parser.parse_args(args)


def main(*argv: str) -> int:
    args = parse_args(argv)

    if args.command == "bump":
        flag_set = args.major or args.minor or args.patch
        if flag_set:
            version = find_latest_version()
            next_version = increment_version(
                version, major=args.major, minor=args.minor, patch=args.patch
            )
        else:
            next_version = args.version
        try:
            bump_version(next_version)
        except RuntimeError as e:
            sys.exit(f"[!] {e!s}")
    elif args.command == "version":
        try:
            print(find_latest_version(), end="")
        except RuntimeError as e:
            sys.exit(f"[!] {e!s}")
    elif args.command == "changelog":
        try:
            version = find_latest_version() if args.version is None else args.version
            changelog = extract_changelog()
        except RuntimeError as e:
            sys.exit(f"[!] {e!s}")
        if version not in changelog:
            sys.exit(f"[!] {version} not in changelog")
        print(changelog[version], end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
