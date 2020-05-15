import argparse
import configparser
import hashlib
import logging
import shlex
import os
import re
import json
import random
import subprocess
import string
import tempfile
from shutil import copyfile

import requests
from drakrun.drakpdb import fetch_pdb, make_pdb_profile
from requests import RequestException

logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s][%(levelname)s] %(message)s',
                    handlers=[logging.StreamHandler()])

# this can be overriden by launcher
LIB_DIR = os.path.dirname(os.path.realpath(__file__))
ETC_DIR = os.path.dirname(os.path.realpath(__file__))
MAIN_DIR = os.path.dirname(os.path.realpath(__file__))

FNULL = open(os.devnull, 'w')


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
    conf_patched = False

    minio_access_key = conf.get('minio', 'access_key')
    out_interface = conf.get('drakrun', 'out_interface')

    if not out_interface:
        default_if = find_default_interface()

        if default_if:
            logging.info(f"Detected default network interface: {default_if}")
            conf['drakrun']['out_interface'] = default_if
            conf_patched = True
        else:
            logging.warning("Unable to detect default network interface.")

    if os.path.exists("/etc/drakcore/config.ini"):
        if not minio_access_key:
            logging.info("Detected single-node setup, copying minio and redis sections from /etc/drakcore/config.ini")
            core_conf = configparser.ConfigParser()
            core_conf.read("/etc/drakcore/config.ini")

            conf['redis'] = core_conf['redis']
            conf['minio'] = core_conf['minio']
            conf_patched = True

    if conf_patched:
        with open(os.path.join(ETC_DIR, "config.ini"), "w") as f:
            conf.write(f)


def install(storage_backend, disk_size, iso_path, zfs_tank_name, max_vms, unattended_xml):
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

    with open(os.path.join(ETC_DIR, "install.json"), "w") as f:
        install_info = {"storage_backend": storage_backend,
                        "disk_size": disk_size,
                        "iso_path": os.path.abspath(iso_path),
                        "zfs_tank_name": zfs_tank_name,
                        "max_vms": max_vms,
                        "enable_unattended": unattended_xml is not None,
                        "iso_sha256": iso_sha256}
        f.write(json.dumps(install_info, indent=4))

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

    if storage_backend == "qcow2":
        try:
            subprocess.check_output("qemu-img --version", shell=True)
        except subprocess.CalledProcessError:
            logging.exception("Failed to determine qemu-img version. Make sure you have qemu-utils installed.")
            return

        try:
            subprocess.check_output(' '.join([
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                os.path.join(LIB_DIR, "volumes/vm-0.img"),
                shlex.quote(disk_size)
            ]), shell=True)
        except subprocess.CalledProcessError:
            logging.exception("Failed to create a new volume using qemu-img.")
            return
    elif storage_backend == "zfs":
        try:
            subprocess.check_output("zfs -?", shell=True)
        except subprocess.CalledProcessError:
            logging.exception("Failed to execute zfs command. Make sure you have ZFS support installed.")
            return

        vm0_vol = shlex.quote(os.path.join(zfs_tank_name, 'vm-0'))

        try:
            subprocess.check_output(f"zfs destroy -Rfr {vm0_vol}", stderr=subprocess.STDOUT, shell=True)
        except subprocess.CalledProcessError as e:
            if b'dataset does not exist' not in e.output:
                logging.exception(f"Failed to destroy the existing ZFS volume {vm0_vol}.")
                return

        try:
            subprocess.check_output(' '.join([
                "zfs",
                "create",
                "-V",
                shlex.quote(disk_size),
                shlex.quote(os.path.join(zfs_tank_name, 'vm-0'))
            ]), shell=True)
        except subprocess.CalledProcessError:
            logging.exception("Failed to create a new volume using zfs create.")
            return
    else:
        raise RuntimeError('Unknown storage backend type.')

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


def generate_profiles(no_report=False):
    if os.path.exists(os.path.join(ETC_DIR, "no_usage_reports")):
        no_report = True

    with open(os.path.join(ETC_DIR, "install.json"), 'r') as f:
        install_info = json.loads(f.read())

    max_vms = int(install_info["max_vms"])
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
    kernel_profile = os.path.join(LIB_DIR, 'profiles/kernel.json')
    with open(kernel_profile, 'w') as f:
        f.write(profile)

    output = subprocess.check_output(['vmi-win-offsets', 'name', 'vm-0', '-r', kernel_profile], timeout=30).decode('utf-8')

    offsets = re.findall(r'^([a-z_]+):(0x[0-9a-f]+)$', output, re.MULTILINE)
    if not offsets:
        logging.error("Failed to parse output of vmi-win-offsets.")
        return

    offsets_dict = {k: v for k, v in offsets}

    if 'kpgd' not in offsets_dict:
        logging.error("Failed to obtain KPGD value.")
        return

    pid_tool = os.path.join(MAIN_DIR, "tools/get-explorer-pid")
    explorer_pid_s = subprocess.check_output([pid_tool, "vm-0", kernel_profile, offsets_dict['kpgd']], timeout=30).decode('ascii', 'ignore')
    m = re.search(r'explorer\.exe:([0-9]+)', explorer_pid_s)
    explorer_pid = m.group(1)

    runtime_profile = {"vmi_offsets": offsets_dict, "inject_pid": explorer_pid}

    logging.info("Saving runtime profile...")
    with open(os.path.join(LIB_DIR, 'profiles/runtime.json'), 'w') as f:
        f.write(json.dumps(runtime_profile, indent=4))

    # TODO (optional) making usermode profiles (a special tool for GUID extraction is required)
    logging.info("Saving VM snapshot...")
    subprocess.check_output('xl save vm-0 ' + os.path.join(LIB_DIR, "volumes/snapshot.sav"), shell=True)

    logging.info("Snapshot was saved succesfully.")

    if install_info["storage_backend"] == 'zfs':
        snap_name = shlex.quote(os.path.join(install_info["zfs_tank_name"], 'vm-0@booted'))
        subprocess.check_output(f'zfs snapshot {snap_name}', shell=True)

    for vm_id in range(max_vms + 1):
        # we treat vm_id=0 as special internal one
        generate_vm_conf(install_info, vm_id)

    if not no_report:
        send_usage_report({
            "kernel": {
                "guid": pdb,
                "filename": fn,
                "version": version
            },
            "install_iso": {
                "sha256": install_info["iso_sha256"]
            }
        })

    reenable_services()
    logging.info("All right, drakrun setup is done.")


def reenable_services():
    if not os.path.exists(os.path.join(ETC_DIR, "install.json")):
        logging.info("Not re-enabling services, install.json is missing.")
        return

    with open(os.path.join(ETC_DIR, "install.json"), 'r') as f:
        install_info = json.loads(f.read())

    max_vms = int(install_info["max_vms"])

    subprocess.check_output('systemctl disable \'drakrun@*\'', shell=True, stderr=subprocess.STDOUT)
    subprocess.check_output('systemctl stop \'drakrun@*\'', shell=True, stderr=subprocess.STDOUT)

    for vm_id in range(1, max_vms + 1):
        logging.info("Enabling and starting drakrun@{}...".format(vm_id))
        subprocess.check_output('systemctl enable drakrun@{}'.format(vm_id), shell=True, stderr=subprocess.STDOUT)
        subprocess.check_output('systemctl restart drakrun@{}'.format(vm_id), shell=True, stderr=subprocess.STDOUT)


def generate_vm_conf(install_info, vm_id):
    iso_path = install_info['iso_path']
    storage_backend = install_info['storage_backend']
    zfs_tank_name = install_info['zfs_tank_name']

    with open(os.path.join(ETC_DIR, 'scripts/cfg.template'), 'r') as f:
        template = f.read()

    disks = []

    if storage_backend == "zfs":
        disks.append('phy:/dev/zvol/{tank_name}/vm-{vm_id},hda,w'.format(tank_name=zfs_tank_name, vm_id=vm_id))
    elif storage_backend == "qcow2":
        disks.append('tap:qcow2:{main_dir}/volumes/vm-{vm_id}.img,xvda,w'.format(main_dir=LIB_DIR, vm_id=vm_id))
    else:
        raise RuntimeError('Unknown storage backend.')

    disks.append('file:{iso},hdc:cdrom,r'.format(iso=os.path.abspath(iso_path)))

    if install_info['enable_unattended']:
        disks.append('file:{main_dir}/volumes/unattended.iso,hdd:cdrom,r'.format(main_dir=LIB_DIR))

    disks = ', '.join(['"{}"'.format(disk) for disk in disks])

    template = template.replace('{{ VM_ID }}', str(vm_id))
    template = template.replace('{{ DISKS }}', disks)

    if vm_id == 0:
        template = re.sub('on_reboot[ ]*=(.*)', 'on_reboot = "restart"', template)

    with open(os.path.join(ETC_DIR, 'configs/vm-{}.cfg'.format(vm_id)), 'w') as f:
        f.write(template)

    logging.info("Generated VM configuration for vm-{vm_id}".format(vm_id=vm_id))


def main():
    parser = argparse.ArgumentParser(description='Configure drakrun')
    subparsers = parser.add_subparsers()

    install_p = subparsers.add_parser('install', help='Install guest Virtual Machine')
    install_p.set_defaults(which='install')
    install_p.add_argument('--storage-backend', default='qcow2', type=str, help='Storage backend (default: qcow2)')
    install_p.add_argument('--disk-size', default='100G', type=str, help='Disk size (default: 100G)')
    install_p.add_argument('--zfs-tank-name', type=str, help='Tank name (only for zfs storage backend)')
    install_p.add_argument('--max-vms', default=1, type=str, help='Maximum number of simultaneous VMs (default: 1)')
    install_p.add_argument('--iso', type=str, help='Installation ISO', required=True)
    install_p.add_argument('--unattended-xml', type=str, help='Path to autounattend.xml for automated Windows install (optional)')

    profile_p = subparsers.add_parser('postinstall', help='Perform tasks after guest installation')
    profile_p.set_defaults(which='postinstall')
    profile_p.add_argument('--no-report', dest='no_report', action='store_true', default=False, help='Don\'t send anonymous usage report')

    postupgrade_p = subparsers.add_parser('postupgrade', help='Perform tasks after drakrun upgrade')
    postupgrade_p.set_defaults(which='postupgrade')

    args = parser.parse_args()

    if not hasattr(args, 'which'):
        parser.print_help()
        return

    if os.geteuid() != 0:
        logging.warning('Not running as root, draksetup may work improperly!')

    if args.which == "install":
        install(storage_backend=args.storage_backend,
                disk_size=args.disk_size,
                iso_path=args.iso,
                zfs_tank_name=args.zfs_tank_name,
                max_vms=args.max_vms,
                unattended_xml=args.unattended_xml)
    elif args.which == "postinstall":
        generate_profiles(args.no_report)
    elif args.which == "postupgrade":
        reenable_services()

        with open(os.path.join(ETC_DIR, 'scripts/cfg.template'), 'r') as f:
            template = f.read()

        passwd_characters = string.ascii_letters + string.digits
        passwd = ''.join(random.choice(passwd_characters) for i in range(20))
        template = template.replace('{{ VNC_PASS }}', passwd)

        with open(os.path.join(ETC_DIR, 'scripts/cfg.template'), 'w') as f:
            f.write(template)

        detect_defaults()


if __name__ == "__main__":
    main()
