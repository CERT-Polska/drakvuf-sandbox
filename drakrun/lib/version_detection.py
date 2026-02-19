import dataclasses
import re
import subprocess

MINIMUM_SUPPORTED_DRAKVUF_VERSION = (1, 1)


@dataclasses.dataclass(frozen=True)
class DrakvufVersionInfo:
    major: int
    minor: int
    build: str

    # https://github.com/tklengyel/drakvuf/commit/51aef99281e5abc43a7d24b7e548b68b1bdcaf32
    supports_shellexec_verb: bool
    debug_build: bool


def get_drakvuf_version() -> DrakvufVersionInfo:
    try:
        output = subprocess.run(
            ["drakvuf", "-h"],
            capture_output=True,
            encoding="utf-8",
        )
    except subprocess.CalledProcessError:
        raise RuntimeError(
            "Failed to execute 'drakvuf -h' command. "
            "Make sure you have Drakvuf installed."
        )

    help_string = output.stderr
    version_string = help_string.splitlines()[0]
    match = re.search(r"v(\d+)\.(\d+)-(.+?)\s", version_string)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        build = match.group(3)
    else:
        raise RuntimeError(
            "Failed to extract Drakvuf version from 'drakvuf -h' command. "
            f"Version string is: {version_string}"
        )

    supports_shellexec_verb = "-V <shellexec verb>" in help_string
    debug_build = "-v, --verbose" in help_string
    return DrakvufVersionInfo(
        major=major,
        minor=minor,
        build=build,
        supports_shellexec_verb=supports_shellexec_verb,
        debug_build=debug_build,
    )


def is_drakvuf_supported(version_info: DrakvufVersionInfo) -> bool:
    return (version_info.major, version_info.minor) >= MINIMUM_SUPPORTED_DRAKVUF_VERSION
