import pathlib
import zipfile


def compress_ipt(analysis_dir: pathlib.Path) -> None:
    """
    Compress the directory specified by dirpath to target_zip file.
    """
    # Compress IPT traces, they're quite large however they compress well
    ipt_path = analysis_dir / "ipt"
    ipt_zip_path = analysis_dir / "ipt.zip"

    zipf = zipfile.ZipFile(ipt_zip_path, "w", zipfile.ZIP_DEFLATED)

    for ipt_file in ipt_path.rglob("*"):
        zip_path = ipt_file.relative_to(analysis_dir).as_posix()
        zipf.write(ipt_file, zip_path)
        ipt_file.unlink()
