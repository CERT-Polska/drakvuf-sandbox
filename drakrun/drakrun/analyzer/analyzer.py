import json
import logging
import pathlib
from typing import Optional

from drakrun.lib.drakshell import Drakshell
from drakrun.lib.injector import Injector
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.network_info import NetworkConfiguration
from drakrun.lib.paths import (
    INSTALL_INFO_PATH,
    NETWORK_CONF_PATH,
    VMI_INFO_PATH,
    VMI_KERNEL_PROFILE_PATH,
)

from ..lib.libvmi import VmiInfo
from .analysis_options import AnalysisOptions
from .post_restore import get_post_restore_command
from .postprocessing import postprocess_output_dir
from .run_tools import run_drakvuf, run_tcpdump, run_vm

log = logging.getLogger(__name__)


def prepare_output_dir(output_dir: pathlib.Path):
    ...


def get_network_configuration(options: AnalysisOptions) -> NetworkConfiguration:
    network_conf = NetworkConfiguration.load(NETWORK_CONF_PATH)
    if options.dns_server is not None:
        network_conf.dns_server = options.dns_server
    if options.out_interface is not None:
        network_conf.out_interface = options.out_interface
    if options.net_enable is not None:
        network_conf.net_enable = options.net_enable
    return network_conf


def drop_sample_to_vm(
    injector: Injector, sample_path: pathlib.Path, target_filename: Optional[str] = None
):
    if target_filename is None:
        target_filename = sample_path.name
    target_path = f"%USERPROFILE%\\Desktop\\{target_filename}"
    result = injector.write_file(str(sample_path), target_path)
    try:
        return json.loads(result.stdout)["ProcessName"]
    except ValueError as e:
        log.error(
            "JSON decode error occurred when tried to parse injector's logs. "
            f"Raw log line: {result.stdout}"
        )
        raise e


def analyze_file(options: AnalysisOptions):
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    network_conf = get_network_configuration(options)
    vmi_info = VmiInfo.load(VMI_INFO_PATH)
    kernel_profile_path = VMI_KERNEL_PROFILE_PATH.as_posix()

    with run_vm(options.vm_id, install_info, network_conf) as vm:
        network_info = vm.get_network_info()
        injector = Injector(vm.vm_name, vmi_info, kernel_profile_path)
        drakshell = Drakshell(vm.vm_name)
        drakshell.connect(timeout=10)
        info = drakshell.get_info()

        log.info(f"Drakshell active on: {str(info)}")
        log.info("Running post-restore command...")
        post_restore_cmd = get_post_restore_command(network_conf.net_enable)
        drakshell.check_call(post_restore_cmd)

        if options.sample_path is not None:
            log.info("Copying sample to the VM...")
            guest_path = drop_sample_to_vm(
                injector, options.sample_path, options.target_filename
            )
        else:
            guest_path = None

        tcpdump_file = options.output_dir / "dump.pcap"
        drakmon_file = options.output_dir / "drakmon.log"
        drakvuf_args = ["-a", "procmon"]

        try:
            with run_tcpdump(network_info, tcpdump_file), run_drakvuf(
                vm.vm_name, vmi_info, kernel_profile_path, drakmon_file, drakvuf_args
            ) as drakvuf:
                if guest_path:
                    drakshell.run([guest_path], terminate_drakshell=True)
                else:
                    drakshell.finish()
                log.info("Analysis started...")
                drakvuf.wait()
        except KeyboardInterrupt:
            log.info("Interrupted with CTRL-C, analysis finished.")

        postprocess_output_dir(options.output_dir)
