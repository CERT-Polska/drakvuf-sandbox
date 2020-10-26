import configparser
import hashlib
import logging
import shlex
import os
import re
import json
import time
import random
import subprocess
import string
import tempfile
from shutil import copyfile

import click
import requests
from requests import RequestException
from drakrun.drakpdb import fetch_pdb, make_pdb_profile, dll_file_list, pdb_guid
from drakrun.config import ETC_DIR, LIB_DIR, InstallInfo
from drakrun.storage import get_storage_backend, REGISTERED_BACKEND_NAMES
from drakrun.vmconf import generate_vm_conf
from tqdm import tqdm

logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s][%(levelname)s] %(message)s',
                    handlers=[logging.StreamHandler()])


def find_default_interface():
    routes = subprocess.check_output('ip route show default', shell=True, stderr=subprocess.STDOUT) \
        .decode('ascii').strip().split('\n')

    for route in routes:
        m = re.search(r'dev ([^ ]+)', route.strip())

        if m:
            return m.group(1)

    return None


def detect_defaults():
    os.makedirs(ETC_DIR, exist_ok=True)
    os.makedirs(os.path.join(ETC_DIR, "configs"), exist_ok=True)

    os.makedirs(LIB_DIR, exist_ok=True)
    os.makedirs(os.path.join(LIB_DIR, "profiles"), exist_ok=True)
    os.makedirs(os.path.join(LIB_DIR, "volumes"), exist_ok=True)

    conf = configparser.ConfigParser()
    conf.read(os.path.join(ETC_DIR, "config.ini"))

    out_interface = conf.get('drakrun', 'out_interface')

    if not out_interface:
        default_if = find_default_interface()

        if default_if:
            logging.info(f"Detected default network interface: {default_if}")
            conf['drakrun']['out_interface'] = default_if
        else:
            logging.warning("Unable to detect default network interface.")


def ensure_zfs(ctx, param, value):
    if value is not None and ctx.params['storage_backend'] != "zfs":
        raise click.BadParameter("This parameter is valid only with ZFS backend")
    return value


@click.command(help='Install guest Virtual Machine',
               no_args_is_help=True)
@click.argument('iso_path', type=click.Path(exists=True))
@click.option('--storage-backend', 'storage_backend',
              type=click.Choice(REGISTERED_BACKEND_NAMES, case_sensitive=False),
              default='qcow2',
              show_default=True,
              help='Storage backend', is_eager=True)
@click.option('--disk-size', 'disk_size',
              default='100G',
              show_default=True,
              help='Disk size')
@click.option('--zfs-tank-name', 'zfs_tank_name',
              callback=ensure_zfs,
              help='Tank name (only for ZFS storage backend)')
@click.option('--unattended-xml', 'unattended_xml',
              type=click.Path(exists=True),
              help='Path to autounattend.xml for automated Windows install')
def install(storage_backend, disk_size, iso_path, zfs_tank_name, unattended_xml):
    logging.info("Ensuring that drakrun@* services are stopped...")
    subprocess.check_output('systemctl stop \'drakrun@*\'', shell=True, stderr=subprocess.STDOUT)

    logging.info("Performing installation...")

    if unattended_xml:
        logging.info("Baking unattended.iso for automated installation")
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_xml_path = os.path.join(tmpdir, 'autounattend.xml')

            with open(tmp_xml_path, 'wb') as fw:
                with open(unattended_xml, 'rb') as fr:
                    fw.write(fr.read())

            try:
                subprocess.check_output(['genisoimage', '-o', os.path.join(LIB_DIR, "volumes/unattended.iso"), '-J', '-r', tmp_xml_path], stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError:
                logging.exception("Failed to generate unattended.iso.")

    sha256_hash = hashlib.sha256()

    with open(iso_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

        iso_sha256 = sha256_hash.hexdigest()

    install_info = InstallInfo(
        storage_backend=storage_backend,
        disk_size=disk_size,
        iso_path=os.path.abspath(iso_path),
        zfs_tank_name=zfs_tank_name,
        enable_unattended=unattended_xml is not None,
        iso_sha256=iso_sha256
    )
    install_info.save()

    logging.info("Checking xen-detect...")
    proc = subprocess.run('xen-detect -N', shell=True)

    if proc.returncode != 1:
        logging.error('It looks like the system is not running on Xen. Please reboot your machine into Xen hypervisor.')
        return

    logging.info("Testing if xl tool is sane...")

    try:
        subprocess.check_output('xl info', shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        logging.exception("Failed to test xl command.")
        return

    try:
        subprocess.check_output('xl uptime vm-0', shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        pass
    else:
        logging.info('Detected that vm-0 is already running, stopping it.')
        subprocess.run('xl destroy vm-0', shell=True, check=True)

    generate_vm_conf(install_info, 0)

    backend = get_storage_backend(install_info)
    backend.initialize_vm0_volume(disk_size)

    try:
        subprocess.check_output("brctl show", shell=True)
    except subprocess.CalledProcessError:
        logging.exception("Failed to execute brctl show. Make sure you have bridge-utils installed.")
        return

    try:
        subprocess.check_output('brctl addbr drak0', stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
        if b'already exists' in e.output:
            logging.info("Bridge drak0 already exists.")
        else:
            logging.exception("Failed to create bridge drak0.")

    cfg_path = os.path.join(ETC_DIR, "configs/vm-0.cfg")

    try:
        subprocess.run('xl create {}'.format(shlex.quote(cfg_path)), shell=True, check=True)
    except subprocess.CalledProcessError:
        logging.exception("Failed to launch VM vm-0")
        return

    logging.info("-" * 80)
    logging.info("Initial VM setup is complete and the vm-0 was launched.")
    logging.info("Please now VNC to the port 5900 on this machine to perform Windows installation.")
    logging.info("After you have installed Windows and booted it to the desktop, please execute:")
    logging.info("# draksetup postinstall")

    with open(cfg_path, "r") as f:
        data = f.read()
        m = re.search(r'vncpasswd[ ]*=(.*)', data)
        if m:
            passwd = m.group(1).strip()
            if passwd[0] == '"' and passwd[-1] == '"':
                passwd = passwd[1:-1]

            logging.info("Your configured VNC password is:")
            logging.info(passwd)

    logging.info("Please note that on some machines, system installer may boot for up to 10 minutes")
    logging.info("and may look unresponsive during the process. Please be patient.")
    logging.info("-" * 80)


def send_usage_report(report):
    try:
        res = requests.post('https://drakvuf.icedev.pl/usage/draksetup', json=report, timeout=5)
        res.raise_for_status()
    except RequestException:
        logging.exception("Failed to send usage report. This is not a serious problem.")


def create_rekall_profiles(install_info: InstallInfo):
    storage_backend = get_storage_backend(install_info)
    with storage_backend.vm0_root_as_block() as block_device, \
            tempfile.TemporaryDirectory() as mount_path:
        mnt_path_quoted = shlex.quote(mount_path)
        blk_quoted = shlex.quote(block_device)
        try:
            subprocess.check_output(f"mount -t ntfs -o ro {blk_quoted} {mnt_path_quoted}", shell=True)
        except subprocess.CalledProcessError:
            raise RuntimeError(f"Failed to mount {block_device} as NTFS.")

        profiles_path = os.path.join(LIB_DIR, "profiles")
        for file in dll_file_list:
            try:
                logging.info(f"Fetching rekall profile for {file.path}")
                local_dll_path = os.path.join(profiles_path, file.dest)

                copyfile(os.path.join(mount_path, file.path), local_dll_path)
                guid = pdb_guid(local_dll_path)
                tmp = fetch_pdb(guid["filename"], guid["GUID"], profiles_path)

                logging.debug("Parsing PDB into JSON profile...")
                profile = make_pdb_profile(tmp)
                with open(os.path.join(profiles_path, f"{file.dest}.json"), 'w') as f:
                    f.write(profile)
            except FileNotFoundError:
                logging.warning(f"Failed to copy file {file.path}, skipping...")
            except RuntimeError:
                logging.warning(f"Failed to fetch profile for {file.path}, skipping...")
            except Exception:
                logging.warning(f"Unexpected exception while creating rekall profile for {file.path}, skipping...")
            finally:
                if os.path.exists(local_dll_path):
                    os.remove(local_dll_path)
                if os.path.exists(os.path.join(profiles_path, tmp)):
                    os.remove(os.path.join(profiles_path, tmp))

        # cleanup
        subprocess.check_output(f'umount {mnt_path_quoted}', shell=True)


@click.command()
@click.option('--report/--no-report', 'report',
              default=True,
              show_default=True,
              help="Send anonymous usage report")
@click.option('--usermode/--no-usermode', 'generate_usermode',
              default=True,
              show_default=True,
              help="Generate user mode profiles")
def postinstall(report, generate_usermode):
    if os.path.exists(os.path.join(ETC_DIR, "no_usage_reports")):
        report = False

    install_info = InstallInfo.load()
    output = subprocess.check_output(['vmi-win-guid', 'name', 'vm-0'], timeout=30).decode('utf-8')

    try:
        version = re.search(r'Version: (.*)', output).group(1)
        pdb = re.search(r'PDB GUID: ([0-9a-f]+)', output).group(1)
        fn = re.search(r'Kernel filename: ([a-z]+\.[a-z]+)', output).group(1)
    except AttributeError:
        logging.error("Failed to obtain kernel PDB GUID/Kernel filename.")
        return

    logging.info("Determined PDB GUID: {}".format(pdb))
    logging.info("Determined kernel filename: {}".format(fn))

    logging.info("Fetching PDB file...")
    dest = fetch_pdb(fn, pdb, destdir=os.path.join(LIB_DIR, 'profiles/'))

    logging.info("Generating profile out of PDB file...")
    profile = make_pdb_profile(dest)

    logging.info("Saving profile...")
    kernel_profile = os.path.join(LIB_DIR, 'profiles', 'kernel.json')
    with open(kernel_profile, 'w') as f:
        f.write(profile)

    output = subprocess.check_output(['vmi-win-offsets', '--name', 'vm-0', '--json-kernel', kernel_profile], timeout=30).decode('utf-8')

    offsets = re.findall(r'^([a-z_]+):(0x[0-9a-f]+)$', output, re.MULTILINE)
    if not offsets:
        logging.error("Failed to parse output of vmi-win-offsets.")
        return

    offsets_dict = {k: v for k, v in offsets}

    if 'kpgd' not in offsets_dict:
        logging.error("Failed to obtain KPGD value.")
        return

    module_dir = os.path.dirname(os.path.realpath(__file__))
    pid_tool = os.path.join(module_dir, "tools", "get-explorer-pid")
    explorer_pid_s = subprocess.check_output([pid_tool, "vm-0", kernel_profile, offsets_dict['kpgd']], timeout=30).decode('ascii', 'ignore')
    m = re.search(r'explorer\.exe:([0-9]+)', explorer_pid_s)
    explorer_pid = m.group(1)

    runtime_profile = {"vmi_offsets": offsets_dict, "inject_pid": explorer_pid}

    logging.info("Saving runtime profile...")
    with open(os.path.join(LIB_DIR, 'profiles', 'runtime.json'), 'w') as f:
        f.write(json.dumps(runtime_profile, indent=4))

    logging.info("Saving VM snapshot...")
    subprocess.check_output('xl save vm-0 ' + os.path.join(LIB_DIR, "volumes", "snapshot.sav"), shell=True)

    storage_backend = get_storage_backend(install_info)
    storage_backend.snapshot_vm0_volume()
    logging.info("Snapshot was saved succesfully.")

    if generate_usermode:
        try:
            create_rekall_profiles(install_info)
        except RuntimeError as e:
            logging.warning("Generating usermode profiles failed")
            logging.exception(e)

    if report:
        send_usage_report({
            "kernel": {
                "guid": pdb,
                "filename": fn,
                "version": version
            },
            "install_iso": {
                "sha256": install_info.iso_sha256
            }
        })

    logging.info("All right, drakrun setup is done.")
    logging.info("First instance of drakrun will be enabled automatically...")
    subprocess.check_output('systemctl enable drakrun@1', shell=True)
    subprocess.check_output('systemctl start drakrun@1', shell=True)

    logging.info("If you want to have more parallel instances, execute:")
    logging.info("  # draksetup scale <number of instances>")


@click.command(help='Perform tasks after drakrun upgrade')
def postupgrade():
    with open(os.path.join(ETC_DIR, 'scripts/cfg.template'), 'r') as f:
        template = f.read()

    passwd_characters = string.ascii_letters + string.digits
    passwd = ''.join(random.choice(passwd_characters) for i in range(20))
    template = template.replace('{{ VNC_PASS }}', passwd)

    with open(os.path.join(ETC_DIR, 'scripts', 'cfg.template'), 'w') as f:
        f.write(template)

    detect_defaults()


def get_enabled_drakruns():
    for fn in os.listdir("/etc/systemd/system/default.target.wants"):
        if re.fullmatch('drakrun@[0-9]+\\.service', fn):
            yield fn


def wait_processes(descr, popens):
    total = len(popens)

    if total == 0:
        return True

    exit_codes = []

    with tqdm(total=total, unit_scale=True) as pbar:
        pbar.set_description(descr)
        while True:
            time.sleep(0.25)
            for popen in popens:
                exit_code = popen.poll()
                if exit_code is not None:
                    exit_codes.append(exit_code)
                    popens.remove(popen)
                    pbar.update(1)

            if len(popens) == 0:
                return all([exit_code == 0 for exit_code in exit_codes])


@click.command(help='Scale drakrun services',
               no_args_is_help=True)
@click.argument('scale_count',
                type=int)
def scale(scale_count):
    """Enable or disable additional parallel instances of drakrun service.."""
    if scale_count < 1:
        raise RuntimeError('Invalid value of scale parameter. Must be at least 1.')

    cur_services = set(list(get_enabled_drakruns()))
    new_services = set([f'drakrun@{i}.service' for i in range(1, scale_count + 1)])

    disable_services = cur_services - new_services
    enable_services = new_services

    wait_processes('disable services', [subprocess.Popen(["systemctl", "disable", service], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for service in disable_services])
    wait_processes('enable services', [subprocess.Popen(["systemctl", "enable", service], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for service in enable_services])
    wait_processes('start services', [subprocess.Popen(["systemctl", "start", service], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for service in enable_services])
    wait_processes('stop services', [subprocess.Popen(["systemctl", "stop", service], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for service in disable_services])


@click.command(help='Mount ISO into guest',
               no_args_is_help=True)
@click.argument('iso_path',
                type=click.Path(exists=True))
@click.option('--domain', 'domain_name',
              type=str,
              default='vm-0',
              show_default=True,
              help='Domain name (i.e. Virtual Machine name)')
def mount(iso_path, domain_name):
    '''Inject ISO file into specified guest vm.
    Domain can be retrieved by running "xl list" command on the host.
    '''
    iso_path_full = os.path.abspath(iso_path)
    subprocess.run(['xl', 'qemu-monitor-command', domain_name, f'change ide-5632 {iso_path_full}'])


@click.group()
def main():
    pass


main.add_command(install)
main.add_command(postinstall)
main.add_command(postupgrade)
main.add_command(mount)
main.add_command(scale)


if __name__ == "__main__":
    if os.geteuid() != 0:
        logging.warning('Not running as root, draksetup may work improperly!')
    main()
