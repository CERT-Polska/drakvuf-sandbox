# DRAKVUF Sandbox
[![Gitter](https://badges.gitter.im/drakvuf-sandbox/community.svg)](https://gitter.im/drakvuf-sandbox/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge) [![Build Status](https://drone.icedev.pl/api/badges/CERT-Polska/drakvuf-sandbox/status.svg)](https://drone.icedev.pl/CERT-Polska/drakvuf-sandbox)

DRAKVUF Sandbox is an automated black-box malware analysis system with [DRAKVUF](https://drakvuf.com/) engine under the hood, which does not require an agent on guest OS.

This project provides you with a friendly web interface that allows you to upload suspicious files to be analyzed. Once the sandboxing job is finished, you can explore the analysis result through the mentioned interface and get insight whether the file is truly malicious or not.

Because it is usually pretty hard to set up a malware sandbox, this project also provides you with an installer app that would guide you through the necessary steps and configure your system using settings that are recommended for beginners. At the same time, experienced users can tweak some settings or even replace some infrastructure parts to better suit their needs.

![DRAKVUF Sandbox - Analysis view](.github/screenshots/sandbox.png)

## Getting started

### Supported hardware&software

In order to run DRAKVUF Sandbox, your setup must fullfill all of the listed requirements:

* Processor: Intel processor with VT-x and EPT features
* Host system: Debian 10 Buster/Ubuntu 18.04 Bionic/Ubuntu 20.04 Focal with at least 2 core CPU and 5 GB RAM
* Guest system: Windows 7 (x64), Windows 10 (x64; experimental support)

Nested virtualization:

* KVM **does** work, however it is considered experimental. If you experience any bugs, please report them to us for further investigation.
* Due to lack of exposed CPU features, hosting drakvuf-sandbox in cloud is **not** supported (although it might change in the future)
* Hyper-V does **not** work
* Xen **does** work out of the box
* VMware Workstation Player **does** work, but you need to check Virtualize EPT option for a VM; Intel processor with EPT still required

### Basic installation

This instruction assumes that you want to create a single-node installation with the default components, which is recommended for beginners.

1. Download [latest release packages](https://github.com/CERT-Polska/drakvuf-sandbox/releases).
2. Install DRAKVUF:
   ```
   sudo apt update
   sudo apt install ./drakvuf-bundle*.deb
   sudo reboot
   ```
3. Install DRAKVUF Sandbox stack:
   ```
   sudo apt install redis-server
   sudo apt install ./drakcore*.deb
   sudo apt install ./drakrun*.deb
   ```
4. Execute:
   ```
   sudo draksetup install --iso /opt/path_to_windows.iso
   ```
   carefully read the command's output. This command would run a Virtual Machine with Windows system installation process.
   
   **Unattended installation:** If you have `autounattend.xml` matching your Windows ISO, you can request unattended installation by adding `--unattended-xml /path/to/autounattend.xml`. Unattended install configuration could be generated with [Windows Answer File Generator](https://www.windowsafg.com/win10x86_x64.html).
   
   **Storage backend:** By default, DRAKVUF Sandbox is storing virtual machine's HDD in a `qcow2` file. If you want to use ZFS instead, please check the "Optional features" section below.
5. Use VNC to connect to the installation process:
   ```
   vncviewer localhost:5900
   ```
6. Perform Windows installation until you are booted to the desktop.
7. Execute:
   ```
   sudo draksetup postinstall
   ```
   **Note:** Add `--no-report` if you don't want `draksetup` to send [basic usage report](https://github.com/CERT-Polska/drakvuf-sandbox/blob/master/USAGE_STATISTICS.md). 
8. Test your installation by navigating to the web interface ( http://localhost:6300/ ) and uploading some samples. The default analysis time is 10 minutes.

## Optional features

This sections contains various information about optional features that may be enabled when setting up DRAKVUF Sandbox.

### ZFS Storage backend
If you want to install DRAKVUF Sandbox with a ZFS storage backend, you should perform the following extra steps before executing `draksetup install` command:

1. Install ZFS on your machine (guide for: [Debian Buster](https://github.com/openzfs/zfs/wiki/Debian), [Ubuntu 18.04](https://ubuntu.com/tutorials/setup-zfs-storage-pool#2-installing-zfs))
2. Create a ZFS pool on a free partition:
   ```
   zpool create tank <partition_name>
   ```
   where `<partiton_name>` is e.g. `/dev/sda3`. Be aware that all data stored on the selected partition may be erased.
3. Create a dataset for DRAKVUF Sandbox:
   ```
   zfs create tank/vms
   ```
4. Execute `draksetup install` as in "Basic installation" section, but remembering to provide additional command line switches:
   ```
   --storage-backend zfs --zfs-tank-name tank/vms
   ```

### ProcDOT integration
DRAKVUF Sandbox may optionally draw a behavioral graph using [ProcDOT](https://www.procdot.com/), if `drakcore` will find it's binary installed at `/opt/procdot/procmon2dot`.

1. [Download ProcDOT](https://www.procdot.com/downloadprocdotbinaries.htm) (Linux version).
2. With your downloaded `procdot*_linux.zip` archive, execute the following commands:
   ```
   unzip -o procdot*_linux.zip lin64/* -d /tmp/procdot
   mv /tmp/procdot/lin64 /opt/procdot
   chmod +x /opt/procdot/procmon2dot
   ```
3. Your new analysis reports will also contain behavioral graphs.

### Networking (optional)

**Note:** Even though that the guest Internet connectivity is an optional feature, `drakrun` would always make some changes to your host system's network configuration:

Always:

* Each instance of `drakrun@<vm_id>` will create a bridge `drak<vm_id>`, assign `10.13.<vm_id>.1/24` IP address/subnet to it and bring the interface up.
* `drakrun` will drop any INPUT traffic originating from `drak<vm_id>` bridge, except DHCP traffic (UDP ports: 67, 68).

Only with `net_enable=1`:

* `drakrun` will enable IPv4 forwarding.
* `drakrun` will configure MASQUERADE through `out_interface` for packets originating from `10.13.<vm_id>.0/24`.
* `drakrun` will DROP traffic between `drak<X>` and `drak<Y>` bridges for `X != Y`.

In order to find out the exact details of the network configuration, search for `_add_iptable_rule` function usages in `drakrun/drakrun/main.py` file.

#### Basic networking
If you want your guest VMs to access Internet, you can enable networking by editing `[drakrun]`
section in `/etc/drakrun/config.ini`:

* Set `net_enable=1` in order to enable guest Internet access.
* Check if `out_interface` was detected properly (e.g. `ens33`) and if not, correct this setting.

After making changes to `/etc/drakrun`, you need to restart all `drakrun` services that are running
in your system:
 
```
systemctl restart 'drakrun@*'
```

Be aware that if your sandbox instance is already running some analyses, the above command will gracefully
wait up to a few minutes until these are completed.

#### Using dnschef
You may optionally configure your guests to use 

1. Setup [dnschef](https://github.com/iphelix/dnschef) tool.
2. Start `dnschef` in such way to make it listen on all `drak*` interfaces that belong to DRAKVUF Sandbox.
3. Set `dns_server=use-gateway-address` in `/etc/drakrun/config.ini`.
4. Restart your drakrun instances: `systemctl restart 'drakrun@*`

## [Troubleshooting](https://github.com/CERT-Polska/drakvuf-sandbox/wiki/Troubleshooting)

## [Project contents](https://github.com/CERT-Polska/drakvuf-sandbox/wiki/Project-contents)

## [Building installation packages](https://github.com/CERT-Polska/drakvuf-sandbox/wiki/Building-installation-packages)

## Maintainers/authors

Feel free to contact us if you have any questions or comments.

* Michał Leszczyński - monk@cert.pl
* Adam Kliś - bonus@cert.pl
* Hubert Jasudowicz - chivay@cert.pl

You can also reach us on IRC - [#drakvuf-sandbox@irc.freenode.net](https://webchat.freenode.net/#drakvuf-sandbox).

If you have any questions about [DRAKVUF](https://drakvuf.com/) engine itself, contact tamas@tklengyel.com

## CEF Notice

![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/wp-content/uploads/2019/02/en_horizontal_cef_logo-1.png)
