import configparser
import hashlib
import logging
import io
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
from typing import Optional

import click
import requests
from requests import RequestException
from minio import Minio
from minio.error import NoSuchKey
from drakrun.drakpdb import fetch_pdb, make_pdb_profile, dll_file_list, pdb_guid
from drakrun.config import InstallInfo, LIB_DIR, VOLUME_DIR, PROFILE_DIR, ETC_DIR, VM_CONFIG_DIR
from drakrun.networking import setup_vm_network, start_dnsmasq
from drakrun.storage import get_storage_backend, REGISTERED_BACKEND_NAMES
from drakrun.vmconf import generate_vm_conf
from drakrun.util import RuntimeInfo, VmiOffsets
from tqdm import tqdm

logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s][%(levelname)s] %(message)s',
                    handlers=[logging.StreamHandler()])

conf = configparser.ConfigParser()
conf.read(os.path.join(ETC_DIR, "config.ini"))


def find_default_interface():
    routes = subprocess.check_output('ip route show default', shell=True, stderr=subprocess.STDOUT) \
        .decode('ascii').strip().split('\n')

    for route in routes:
        m = re.search(r'dev ([^ ]+)', route.strip())

        if m:
            return m.group(1)

    return None


def ensure_dirs():
    os.makedirs(ETC_DIR, exist_ok=True)
    os.makedirs(VM_CONFIG_DIR, exist_ok=True)

    os.makedirs(LIB_DIR, exist_ok=True)
    os.makedirs(PROFILE_DIR, exist_ok=True)
    os.makedirs(VOLUME_DIR, exist_ok=True)


def detect_defaults():
    ensure_dirs()

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
                subprocess.check_output(['genisoimage', '-o', os.path.join(VOLUME_DIR, "unattended.iso"), '-J', '-r', tmp_xml_path], stderr=subprocess.STDOUT)
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

    net_enable = int(conf['drakrun'].get('net_enable', '0'))
    out_interface = conf['drakrun'].get('out_interface', '')
    dns_server = conf['drakrun'].get('dns_server', '')

    setup_vm_network(vm_id=0, net_enable=net_enable, out_interface=out_interface, dns_server=dns_server)

    if net_enable:
        start_dnsmasq(vm_id=0, dns_server=dns_server, background=True)

    cfg_path = os.path.join(VM_CONFIG_DIR, "vm-0.cfg")

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

        for file in dll_file_list:
            try:
                logging.info(f"Fetching rekall profile for {file.path}")
                local_dll_path = os.path.join(PROFILE_DIR, file.dest)

                copyfile(os.path.join(mount_path, file.path), local_dll_path)
                guid = pdb_guid(local_dll_path)
                tmp = fetch_pdb(guid["filename"], guid["GUID"], PROFILE_DIR)

                logging.debug("Parsing PDB into JSON profile...")
                profile = make_pdb_profile(tmp)
                with open(os.path.join(PROFILE_DIR, f"{file.dest}.json"), 'w') as f:
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
                if os.path.exists(os.path.join(PROFILE_DIR, tmp)):
                    os.remove(os.path.join(PROFILE_DIR, tmp))

        # cleanup
        subprocess.check_output(f'umount {mnt_path_quoted}', shell=True)


def extract_explorer_pid(
    domain: str,
    kernel_profile: str,
    offsets: VmiOffsets,
    timeout: int = 30
) -> Optional[int]:
    """ Call get-explorer-pid helper and get its PID """
    module_dir = os.path.dirname(os.path.realpath(__file__))
    pid_tool = os.path.join(module_dir, "tools", "get-explorer-pid")
    try:
        explorer_pid_s = subprocess.check_output([
            pid_tool,
            domain,
            kernel_profile,
            hex(offsets.kpgd)
        ], timeout=timeout).decode('utf-8', 'ignore')

        m = re.search(r'explorer\.exe:([0-9]+)', explorer_pid_s)
        if m is not None:
            return int(m.group(1))

    except subprocess.CalledProcessError:
        logging.exception("get-explorer-pid exited with an error")
    except subprocess.TimeoutExpired:
        logging.exception("get-explorer-pid timed out")

    raise RuntimeError("Extracting explorer PID failed")


def extract_vmi_offsets(
    domain: str,
    kernel_profile: str,
    timeout: int = 30
) -> Optional[VmiOffsets]:
    """ Call vmi-win-offsets helper and obtain VmiOffsets values """
    try:
        output = subprocess.check_output([
            'vmi-win-offsets',
            '--name', domain,
            '--json-kernel', kernel_profile
        ], timeout=timeout).decode('utf-8', 'ignore')

        return VmiOffsets.from_tool_output(output)
    except TypeError:
        logging.exception("Invalid output of vmi-win-offsets")
    except subprocess.CalledProcessError:
        logging.exception("vmi-win-offsets exited with an error")
    except subprocess.TimeoutExpired:
        logging.exception("vmi-win-offsets timed out")

    raise RuntimeError("Extracting VMI offsets failed")


def eject_cd(domain, drive):
    subprocess.run(["xl", "cd-eject", domain, drive], check=True)


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

    logging.info("Ejecting installation CDs")
    eject_cd("vm-0", "hdc")
    if install_info.enable_unattended:
        # If unattended install is enabled, we have an additional CD-ROM drive
        eject_cd("vm-0", "hdd")

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
    dest = fetch_pdb(fn, pdb, destdir=PROFILE_DIR)

    logging.info("Generating profile out of PDB file...")
    profile = make_pdb_profile(dest)

    logging.info("Saving profile...")
    kernel_profile = os.path.join(PROFILE_DIR, 'kernel.json')
    with open(kernel_profile, 'w') as f:
        f.write(profile)

    vmi_offsets = extract_vmi_offsets('vm-0', kernel_profile)
    explorer_pid = extract_explorer_pid('vm-0', kernel_profile, vmi_offsets)
    runtime_info = RuntimeInfo(vmi_offsets=vmi_offsets, inject_pid=explorer_pid)

    logging.info("Saving runtime profile...")
    with open(os.path.join(PROFILE_DIR, 'runtime.json'), 'w') as f:
        f.write(runtime_info.to_json(indent=4))

    logging.info("Saving VM snapshot...")
    subprocess.check_output('xl save vm-0 ' + os.path.join(VOLUME_DIR, "snapshot.sav"), shell=True)

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


def get_minio_client(config):
    minio_cfg = config['minio']
    return Minio(endpoint=minio_cfg['address'],
                 access_key=minio_cfg['access_key'],
                 secret_key=minio_cfg['secret_key'],
                 secure=minio_cfg.getboolean('secure', fallback=True))


@click.group(help="Manage VM snapshots")
def snapshot():
    pass


@snapshot.command(name='export', help='Upload local snapshot to MinIO.', no_args_is_help=True)
@click.option('--name', required=True, help='Name of the snapshot')
@click.option('--bucket', default='drakrun-snapshots', help='MinIO bucket to store the snapshot')
@click.option('--full', default=False, is_flag=True, help='Upload memory snapshot and profiles')
@click.option('--force', default=False, is_flag=True, help='Overwrite remote snapshot')
def snapshot_export(name, bucket, full, force):
    install_info = InstallInfo.try_load()
    if install_info is None:
        logging.error("Missing installation info. Did you forget to set up the sandbox?")
        return

    mc = get_minio_client(conf)

    if not mc.bucket_exists(bucket):
        logging.error("Bucket %s doesn't exist", bucket)
        return

    if len(list(mc.list_objects(bucket, f"{name}/"))) > 0 and not force:
        logging.error("There are objects in bucket %s at path %s. Aborting...", bucket, f"{name}/")
        return

    logging.info("Exporting snapshot as %s into %s", name, bucket)

    if full:
        logging.warning("Full snapshots may not work if hardware used for "
                        "importing and exporting differs. You have been warned!")
        do_export_full(mc, bucket, name)
    else:
        do_export_minimal(mc, bucket, name)

    logging.info("Done. To use exported snapshot on other machine, execute:")
    logging.info("# draksetup snapshot import --name %s --bucket %s", name, bucket)


@snapshot.command(name='import', help='Download and configure remote snapshot', no_args_is_help=True)
@click.option('--name', required=True, help='Name of the exported snapshot')
@click.option('--bucket', default='drakrun-snapshots', help='MinIO bucket to store the snapshot')
@click.option('--full', default=False, is_flag=True, help='Download VM memory and profiles')
@click.option('--zpool', help='Override zpool name stored in snapshot (only for ZFS snapshots)')
def snapshot_import(name, bucket, full, zpool):
    local_install = InstallInfo.try_load()
    if local_install is not None:
        click.confirm("Detected local snapshot. It will be REMOVED. Continue?", abort=True)

    mc = get_minio_client(conf)

    if not mc.bucket_exists(bucket):
        logging.error("Bucket %s doesn't exist", bucket)
        return

    ensure_dirs()

    try:
        if full:
            logging.warning("Importing full snapshot. This may not work if hardware is different")
            do_import_full(mc, name, bucket, zpool)
        else:
            do_import_minimal(mc, name, bucket, zpool)

            # This could probably use some refactoring
            # We're duplicating quite a lot of code from install function
            install_info = InstallInfo.load()
            generate_vm_conf(install_info, 0)
            backend = get_storage_backend(install_info)
            backend.rollback_vm_storage(0)

            net_enable = int(conf['drakrun'].get('net_enable', '0'))
            out_interface = conf['drakrun'].get('out_interface', '')
            dns_server = conf['drakrun'].get('dns_server', '')
            setup_vm_network(
                vm_id=0,
                net_enable=net_enable,
                out_interface=out_interface,
                dns_server=dns_server
            )

            if net_enable:
                start_dnsmasq(vm_id=0, dns_server=dns_server, background=True)

            cfg_path = os.path.join(VM_CONFIG_DIR, "vm-0.cfg")

            try:
                subprocess.run(['xl' 'create', cfg_path], check=True)
            except subprocess.CalledProcessError:
                logging.exception("Failed to launch VM vm-0")
                return

            logging.info("Minimal snapshots require postinstall to work correctly")
            logging.info("Please VNC to the port 5900 to ensure the OS booted correctly")
            logging.info("After that, execute this command to finish the setup")
            logging.info("# draksetup postinstall")
    except NoSuchKey:
        logging.error("Import failed. Missing files in bucket.")


def do_export_minimal(mc, bucket, name):
    """ Perform minimal snapshot export, symmetric to do_import_minimal """
    logging.info("Uploading installation info")
    install_info = InstallInfo.load()
    install_data = json.dumps(install_info.to_dict()).encode()
    mc.put_object(bucket, f"{name}/install.json", io.BytesIO(install_data), len(install_data))

    logging.info("Uploading VM template")
    mc.fput_object(bucket, f"{name}/cfg.template", os.path.join(ETC_DIR, "scripts", "cfg.template"))

    with tempfile.NamedTemporaryFile() as disk_image:
        logging.info("Exporting VM hard drive")
        storage = get_storage_backend(install_info)
        storage.export_vm0(disk_image.name)

        logging.info("Uploading disk.img")
        mc.fput_object(bucket, f"{name}/disk.img", disk_image.name)


def do_import_minimal(mc, name, bucket, zpool):
    """ Perform minimal snapshot import, symmetric to do_export_minimal """
    logging.info("Downloading installation info")
    mc.fget_object(bucket, f"{name}/install.json",
                   os.path.join(ETC_DIR, InstallInfo._INSTALL_FILENAME))

    logging.info("Downloading VM config")
    mc.fget_object(bucket, f"{name}/cfg.template", os.path.join(ETC_DIR, "scripts", "cfg.template"))

    # Now we have imported InstallInfo object
    install_info = InstallInfo.load()

    # Patch ZFS pool name
    if zpool is not None:
        install_info.zfs_tank_name = zpool
        # Save patched ZFS dataset name (storage backend has to know it)
        install_info.save()

    storage = get_storage_backend(install_info)

    with tempfile.NamedTemporaryFile() as disk_image:
        logging.info("Downloading VM disk image")
        mc.fget_object(bucket, f"{name}/disk.img", disk_image.name)

        logging.info("Importing VM disk")
        storage.import_vm0(disk_image.name)


def do_export_full(mc, bucket, name):
    """ Perform full snapshot export, symmetric to do_import_full """
    do_export_minimal(mc, bucket, name)

    with tempfile.NamedTemporaryFile() as compressed_snapshot:
        # Compress snapshot
        logging.info("Compressing snapshot.sav")
        subprocess.check_call(
            ["gzip", "-c", os.path.join(VOLUME_DIR, "snapshot.sav")],
            stdout=compressed_snapshot,
        )

        logging.info("Uploading snapshot.sav.gz")
        mc.fput_object(bucket, f"{name}/snapshot.sav.gz", compressed_snapshot.name)

    # Upload profiles
    for file in os.listdir(PROFILE_DIR):
        logging.info("Uploading profile %s", file)
        mc.fput_object(bucket, f"{name}/profiles/{file}", os.path.join(PROFILE_DIR, file))


def do_import_full(mc, name, bucket, zpool):
    """ Perform full snapshot import, symmetric to do_export_full """
    do_import_minimal(mc, name, bucket, zpool)

    with tempfile.NamedTemporaryFile() as compressed_snapshot:
        mc.fget_object(bucket, f"{name}/snapshot.sav.gz", compressed_snapshot.name)

        logging.info("Decompressing VM snapshot")
        with open(os.path.join(VOLUME_DIR, "snapshot.sav"), "wb") as snapshot:
            subprocess.run(
                ["zcat", compressed_snapshot.name],
                stdout=snapshot,
                check=True
            )

    profile_prefix = f"{name}/profiles/"
    for object in mc.list_objects(bucket, prefix=profile_prefix):
        # Strip profile prefix
        profile_name = object.name[profile_prefix:]
        mc.fget_object(bucket, object.name, os.path.join(PROFILE_DIR, profile_name))


@click.group()
def main():
    pass


main.add_command(install)
main.add_command(postinstall)
main.add_command(postupgrade)
main.add_command(mount)
main.add_command(scale)
main.add_command(snapshot)


if __name__ == "__main__":
    if os.geteuid() != 0:
        logging.warning('Not running as root, draksetup may work improperly!')
    main()
