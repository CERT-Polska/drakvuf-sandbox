import gzip
import pathlib
import shutil

from drakrun.lib.config import load_config


def gzip_syscalls(analysis_dir: pathlib.Path) -> None:
    """
    Compress syscall.log using gzip if gzip_syscalls configuration option is True.
    This will disable preview of these logs in web.
    """
    config = load_config()
    if not config.drakrun.gzip_syscalls:
        return
    syscall_log = analysis_dir / "syscall.log"
    syscall_log_gz = analysis_dir / "syscall.log.gz"
    with syscall_log.open("rb") as f_in:
        with gzip.open(syscall_log_gz, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    syscall_log.unlink()
