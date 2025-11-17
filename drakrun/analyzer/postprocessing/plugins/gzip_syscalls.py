import gzip
import shutil

from drakrun.lib.config import load_config
from .plugin_base import PostprocessContext

def gzip_syscalls(context: PostprocessContext) -> None:
    """
    Compress syscall.log using gzip if gzip_syscalls configuration option is True.
    This will disable preview of these logs in web.
    """
    analysis_dir = context.analysis_dir
    config = load_config()
    if not config.drakrun.gzip_syscalls:
        return
    
    for name in ["syscall", "sysret"]:
        log_path = analysis_dir / f"{name}.log"
        log_path_gz = analysis_dir / f"{name}.log.gz"
        if log_path.exists():
            with log_path.open("rb") as f_in:
                with gzip.open(log_path_gz, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
        log_path.unlink()
