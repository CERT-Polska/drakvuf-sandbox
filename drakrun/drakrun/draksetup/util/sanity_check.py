import logging
import subprocess
import tempfile

from drakrun.lib.paths import PACKAGE_DIR
from drakrun.lib.vm import VirtualMachine

log = logging.getLogger(__name__)


def sanity_check():
    log.info("Checking xen-detect...")
    proc = subprocess.run("xen-detect -N", shell=True)

    if proc.returncode != 1:
        log.error(
            "It looks like the system is not running on Xen. Please reboot your machine into Xen hypervisor."
        )
        return False

    log.info("Testing if xl tool is sane...")

    try:
        subprocess.run(
            "xl info",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except subprocess.CalledProcessError:
        log.exception(
            "Failed to test xl info command. There might be some dependency problem (please execute 'xl info' manually to find out)."
        )
        return False

    try:
        subprocess.run(
            "xl list",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=10,
        )
    except subprocess.SubprocessError:
        log.exception(
            "Failed to test xl list command. There might be a problem with xen services (check 'systemctl status xenstored', 'systemctl status xenconsoled')."
        )
        return False

    if not perform_xtf():
        log.error("Your Xen installation doesn't pass the necessary tests.")
        return False

    return True


def perform_xtf():
    log.info("Testing your Xen installation...")
    cfg_path = (PACKAGE_DIR / "tools/test-hvm64-example.cfg").as_posix()
    firmware_path = (PACKAGE_DIR / "tools/test-hvm64-example").as_posix()

    with open(cfg_path, "r") as f:
        test_cfg = (
            f.read().replace("{{ FIRMWARE_PATH }}", firmware_path).encode("utf-8")
        )

    with tempfile.NamedTemporaryFile() as tmpf:
        tmpf.write(test_cfg)
        tmpf.flush()

        test_hvm64 = VirtualMachine(None, None, "test-hvm64-example", tmpf.name)
        log.info("Checking if the test domain already exists...")
        test_hvm64.destroy()

        log.info("Creating new test domain...")
        test_hvm64.create(pause=True, timeout=30)

        test_altp2m_tool = (PACKAGE_DIR / "tools/test-altp2m").as_posix()

        log.info("Testing altp2m feature...")
        try:
            subprocess.run(
                [test_altp2m_tool, "test-hvm64-example"],
                stderr=subprocess.STDOUT,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            output = e.output.decode("utf-8", "replace")
            log.error(
                f"Failed to enable altp2m on domain. Your hardware might not support Extended Page Tables. Logs:\n{output}"
            )
            test_hvm64.destroy()
            return False

        log.info("Performing simple XTF test...")
        p = subprocess.Popen(
            ["xl", "console", "test-hvm64-example"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        test_hvm64.unpause(timeout=30)
        stdout_b, _ = p.communicate(timeout=10)

        stdout_text = stdout_b.decode("utf-8")
        stdout = [line.strip() for line in stdout_text.split("\n")]

        for line in stdout:
            if line == "Test result: SUCCESS":
                log.info(
                    "All tests passed. Your Xen installation seems to work properly."
                )
                return True

    log.error(
        f"Preflight check with Xen Test Framework doesn't pass. Your hardware might not support VT-x. Logs: \n{stdout_text}"
    )
    return False
