import json
import logging
import pathlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Set

from drakrun.lib.config import DrakrunConfig
from drakrun.lib.drakshell import Drakshell
from drakrun.lib.injector import Injector

from .analysis_options import AnalysisOptions
from .post_restore import prepare_ps_command
from .startup_command import get_sample_filename_from_host_path

log = logging.getLogger(__name__)

DISK_IMAGE_EXTENSIONS: Set[str] = {".vhd", ".vhdx", ".iso", ".img"}


@dataclass
class PreparedSampleInfo:
    guest_executable_path: str
    guest_working_directory: str
    guest_target_directory: str


class FileHandler(ABC):
    """
    Base class for file handlers.

    Each handler is responsible for:
    - Detecting if it can handle a given file type
    - Preparing the file for analysis (extracting, mounting, etc.)
    """

    @abstractmethod
    def can_handle(self, sample_path: pathlib.Path, options: AnalysisOptions) -> bool:
        """Return True if this handler can process the given file."""
        pass

    @abstractmethod
    def prepare(
        self,
        config: DrakrunConfig,
        drakshell: Drakshell,
        injector: Injector,
        sample_path: pathlib.Path,
        options: AnalysisOptions,
    ) -> PreparedSampleInfo:
        """Prepare the file for analysis and return information about it."""
        pass


def drop_sample_to_vm(
    injector: Injector, sample_path: pathlib.Path, target_path: str
) -> str:
    result = injector.write_file(str(sample_path), target_path)
    try:
        return json.loads(result.stdout)["ProcessName"]
    except ValueError as e:
        log.error(
            "JSON decode error occurred when tried to parse injector's logs. "
            f"Raw log line: {result.stdout}"
        )
        raise e


class ArchiveHandler(FileHandler):
    """
    Handler for extractable archives.
    Supports both 7-Zip and PowerShell Expand-Archive extraction methods.
    """

    def can_handle(self, sample_path: pathlib.Path, options: AnalysisOptions) -> bool:
        """Check if extract_archive is enabled"""
        if options.extract_archive:
            return True

    def prepare(
        self,
        config: DrakrunConfig,
        drakshell: Drakshell,
        injector: Injector,
        sample_path: pathlib.Path,
        options: AnalysisOptions,
    ) -> PreparedSampleInfo:
        """Extract archive on the VM."""
        # If sample_filename is not explicitly defined, get target archive file name
        if options.sample_filename is None:
            options.sample_filename = get_sample_filename_from_host_path(sample_path)

        guest_archive_name = options.sample_filename
        guest_target_directory = options.guest_target_directory
        archive_password = options.archive_password

        guest_archive_target_path = guest_target_directory / pathlib.PureWindowsPath(
            guest_archive_name
        )

        log.info(
            f"Copying archive to the VM ({sample_path.as_posix()} -> {guest_archive_target_path})..."
        )
        guest_archive_resolved_path = drop_sample_to_vm(
            injector, sample_path, str(guest_archive_target_path)
        )

        guest_extraction_dir = pathlib.PureWindowsPath(
            guest_archive_resolved_path
        ).parent

        if config.drakrun.use_7zip:
            log.info(
                f"Expanding archive using 7-Zip {guest_archive_resolved_path} -> {guest_extraction_dir}..."
            )
            command = [
                config.drakrun.path_to_7zip,
                "x",
                str(guest_archive_resolved_path),
                "-o" + str(guest_extraction_dir),
                *(["-p" + archive_password] if archive_password else []),
            ]
        else:
            log.info(
                f"Expanding archive using Expand-Archive {guest_archive_resolved_path} -> {guest_extraction_dir}..."
            )
            command = prepare_ps_command(
                f"Expand-Archive -Force {guest_archive_resolved_path} {guest_extraction_dir}"
            )

        drakshell.check_call(command)

        # Determine executable path and working directory
        archive_executable_path = ""
        if options.start_command is None:
            if not options.guest_archive_entry_path:
                raise ValueError(
                    "Archive handler requires guest_archive_entry_path when start_command is not provided"
                )
            archive_executable_path = str(
                guest_extraction_dir / options.guest_archive_entry_path
            )

            # Set working directory to the archive entry's parent directory
            if options.guest_working_directory is None:
                options.guest_working_directory = pathlib.PureWindowsPath(
                    archive_executable_path
                ).parent
        elif options.guest_working_directory is None:
            options.guest_working_directory = guest_extraction_dir

        guest_working_directory = str(options.guest_working_directory)
        guest_target_directory_str = str(guest_target_directory)

        return PreparedSampleInfo(
            guest_executable_path=archive_executable_path,
            guest_working_directory=guest_working_directory,
            guest_target_directory=guest_target_directory_str,
        )


class DiskImageHandler(FileHandler):
    """
    Handler for disk images.

    Mounts the disk image and automatically selects
    an executable to run based on heuristics.
    """

    EXECUTABLE_EXTENSIONS = [".exe", ".lnk", ".msi", ".bat", ".cmd", ".ps1", ".js"]

    def can_handle(self, sample_path: pathlib.Path, options: AnalysisOptions) -> bool:
        """Check if this is a disk image."""
        # Check target filename extension if set, otherwise check host path
        check_ext = (options.sample_filename or sample_path.name).split(".")[-1].lower()
        return f".{check_ext}" in DISK_IMAGE_EXTENSIONS

    def prepare(
        self,
        config: DrakrunConfig,
        drakshell: Drakshell,
        injector: Injector,
        sample_path: pathlib.Path,
        options: AnalysisOptions,
    ) -> PreparedSampleInfo:
        """Mount disk image on the VM and select executable to run."""
        # If sample_filename is not explicitly defined, get target file name
        if options.sample_filename is None:
            options.sample_filename = get_sample_filename_from_host_path(sample_path)

        guest_disk_path = options.guest_target_directory / options.sample_filename

        log.info(
            f"Copying disk image to the VM ({sample_path.as_posix()} -> {guest_disk_path})..."
        )
        guest_disk_resolved_path = drop_sample_to_vm(
            injector, sample_path, str(guest_disk_path)
        )

        log.info("Getting existing drives...")
        get_drives_before = prepare_ps_command(
            "$ProgressPreference = 'SilentlyContinue'; Get-Volume | Select-Object -ExpandProperty DriveLetter"
        )
        exit_before, stdout_before = drakshell.run_and_capture(get_drives_before)
        if exit_before != 0:
            raise RuntimeError(
                f"Failed to get existing drives, exit code: {exit_before}"
            )

        drives_before = set(stdout_before.strip().split())
        log.info(f"Mounting disk image: {guest_disk_resolved_path}")
        mount_command = ["explorer.exe", guest_disk_resolved_path]
        try:
            process = drakshell.run_interactive(mount_command)
            process.join()
        except Exception as e:
            log.debug(f"Failed to mount image using explorer: {e}")

        time.sleep(3)

        log.info("Finding new drive letter...")
        get_drives_after = prepare_ps_command(
            "$ProgressPreference = 'SilentlyContinue'; Get-Volume | Select-Object -ExpandProperty DriveLetter"
        )
        exit_after, stdout_after = drakshell.run_and_capture(get_drives_after)
        if exit_after != 0:
            raise RuntimeError(
                f"Failed to get drives after mounting, exit code: {exit_after}"
            )
        drives_after = set(stdout_after.strip().split())
        new_drives = drives_after - drives_before
        if not new_drives:
            raise RuntimeError(f"No new drive found after mounting disk image. Drives: {drives_after}")

        drive_letter = list(new_drives)[0]
        log.info(f"Mounted as drive: {drive_letter}:\\")

        mount_point = f"{drive_letter}:\\"

        if options.guest_archive_entry_path:
            executable_path = str(
                pathlib.PureWindowsPath(mount_point) / options.guest_archive_entry_path
            )
        else:
            executable_path = self._select_executable(drakshell, mount_point)

        log.info(f"Selected executable for analysis: {executable_path}")

        guest_working_directory = str(
            pathlib.PureWindowsPath(executable_path).parent
            if options.guest_working_directory is None
            else options.guest_working_directory
        )

        return PreparedSampleInfo(
            guest_executable_path=executable_path,
            guest_working_directory=guest_working_directory,
            guest_target_directory=str(options.guest_target_directory),
        )

    def _select_executable(self, drakshell: Drakshell, mount_point: str) -> str:
        log.info(f"Searching for executables in {mount_point}...")

        ext_patterns = ",".join(f"*{ext}" for ext in self.EXECUTABLE_EXTENSIONS)
        search_command = prepare_ps_command(
            f"Get-ChildItem -Path '{mount_point}' -Recurse -Include {ext_patterns} "
            f"-ErrorAction SilentlyContinue | "
            f"Where-Object {{ !$_.PSIsHidden -and !$_.PSIsContainer }} | "
            f"Select-Object -ExpandProperty FullName"
        )

        exit_code, output = drakshell.run_and_capture(search_command)
        if exit_code != 0:
            raise RuntimeError(f"Failed to list files, exit code: {exit_code}")

        # Parse output and filter by extension priority
        files = [line.strip() for line in output.strip().splitlines() if line.strip()]

        ext_priority = {
            ext.lower(): i for i, ext in enumerate(self.EXECUTABLE_EXTENSIONS)
        }

        for filepath in files:
            ext = pathlib.Path(filepath).suffix.lower()
            if ext in ext_priority:
                log.info(f"Found {ext} file: {filepath}")
                return filepath

        raise RuntimeError("No executable found in disk image")


class NormalFileHandler(FileHandler):
    """Handler for normal files (executables, scripts, etc.)."""

    def can_handle(self, sample_path: pathlib.Path, options: AnalysisOptions) -> bool:
        return not options.extract_archive

    def prepare(
        self,
        config: DrakrunConfig,
        drakshell: Drakshell,
        injector: Injector,
        sample_path: pathlib.Path,
        options: AnalysisOptions,
    ) -> PreparedSampleInfo:
        """Copy file to the VM."""
        # If sample_filename is not explicitly defined, get target file name
        if options.sample_filename is None:
            options.sample_filename = get_sample_filename_from_host_path(sample_path)

        # Determine the full executable path on guest VM
        lower_target_name = options.sample_filename.lower()
        if not lower_target_name.startswith("c:") and not lower_target_name.startswith(
            "%"
        ):
            # Relative path: append to target directory
            guest_executable_path = (
                options.guest_target_directory / options.sample_filename
            )
        else:
            # Absolute path: use as-is
            guest_executable_path = pathlib.PureWindowsPath(options.sample_filename)

        log.info(
            f"Copying sample to the VM ({sample_path.as_posix()} -> {guest_executable_path})..."
        )
        guest_executable_path = drop_sample_to_vm(
            injector, sample_path, str(guest_executable_path)
        )

        resolved_guest_executable_dir = pathlib.PureWindowsPath(
            guest_executable_path
        ).parent

        if options.guest_working_directory is None:
            options.guest_working_directory = resolved_guest_executable_dir

        guest_working_directory = str(options.guest_working_directory)
        guest_target_directory_str = str(options.guest_target_directory)

        return PreparedSampleInfo(
            guest_executable_path=guest_executable_path,
            guest_working_directory=guest_working_directory,
            guest_target_directory=guest_target_directory_str,
        )


FILE_HANDLERS: List[FileHandler] = [  # ordered from most specific
    DiskImageHandler(),
    ArchiveHandler(),
    NormalFileHandler(),
]


def get_handler_for_file(
    sample_path: pathlib.Path, options: AnalysisOptions
) -> Optional[FileHandler]:
    for handler in FILE_HANDLERS:
        if handler.can_handle(sample_path, options):
            return handler
    return None
