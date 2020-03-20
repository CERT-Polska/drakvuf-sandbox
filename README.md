# DRAKVUF Sandbox

DRAKVUF Sandbox is an automated black-box malware analysis system with [DRAKVUF](https://drakvuf.com/) engine under the hood.

This project provides you with a friendly web interface that allows you to upload suspicious files to be analyzed. Once the sandboxing job is finished, you can explore the analysis result through the mentioned interface and get insight whether the file is truly malicious or not.

Because it is usually pretty hard to set up a malware sandbox, this project also provides you with an installer app that would guide you through the necessary steps and configure your system using settings that are recommended for beginners. At the same time, experienced users can tweak some settings or even replace some infrastructure parts to better suit their needs.

## Getting started

### Supported hardware&software

In order to run DRAKVUF Sandbox, your setup must fullfill all of the listed requirements:

* Processor: Intel processor with VT-x and EPT features
* Host system: Debian Buster with at least 2 core CPU and 5 GB RAM
* Guest system: Windows 7 (x64), Windows 10 (x64; experimental support)

### Basic installation

This instruction assumes that you want to create a single-node installation with the default components, which is recommended for beginners.

1. Download [latest release packages](https://github.com/CERT-Polska/drakvuf-sandbox/releases).
2. Install DRAKVUF:
   ```
   sudo apt-get update
   sudo apt-get install -y libpixman-1-0 libpng16-16 libnettle6 libgnutls30 libfdt1 libglib2.0-0 libglib2.0-dev libjson-c3 libyajl2 libaio1
   sudo dpkg -i drakvuf-bundle*.deb
   sudo reboot
   ```
3. Install DRAKVUF Sandbox stack:
   ```
   sudo apt-get install -y python3.7 libpython3.7 python3-distutils tcpdump genisoimage qemu-utils bridge-utils
   sudo apt-get install -y redis-server
   sudo dpkg -i drakcore*.deb
   sudo dpkg -i drakrun*.deb
   ```
4. Execute:
   ```
   sudo draksetup install --iso /opt/path_to_windows.iso
   ```
   carefully read the command's output. This command would run a Virtual Machine with Windows system installation process.
   
   **Unattended installation:** If you have `autounattend.xml` matching your Windows ISO, you can request unattended installation by adding `--unattended-xml /path/to/autounattend.xml`. Unattended install configuration could be generated with [Windows Answer File Generator](https://www.windowsafg.com/win10x86_x64.html).
5. Use VNC to connect to the installation process:
   ```
   vncviewer localhost:5900
   ```
6. Perform Windows installation until you are booted to the desktop.
7. Execute:
   ```
   sudo draksetup postinstall
   ```
8. Test installation using web interface: http://localhost:6300/

### ProcDOT integration (optional)
DRAKVUF Sandbox may optionally draw a behavioral graph using [ProcDOT](https://www.procdot.com/), if `drakcore` will find it's binary installed at `/opt/procdot/procmon2dot`.

1. [Download ProcDOT](https://www.procdot.com/downloadprocdotbinaries.htm) (Linux version).
2. With your downloaded `procdot*_linux.zip` archive, execute the following commands:
   ```
   unzip -o procdot*_linux.zip lin64/* -d /tmp/procdot
   mv /tmp/procdot/lin64 /opt/procdot
   chmod +x /opt/procdot/procmon2dot
   ```
3. Your new analyses will also display behavioral graphs.

### Troubleshooting

If your DRAKVUF Sandbox installation seems to work improperly, here are some commands that would help to troubleshoot the infrastructure.

Check the status of web interface service:
```
systemctl status drak-web
journalctl -e -u drak-web
```

Check the status of internal queue system:
```
systemctl status drak-system
journalctl -e -u drak-system
```

Check the status of builtin object storage:
```
systemctl status drak-minio
journalctl -e -u drak-minio
```

Check the status of first sandbox worker:
```
systemctl status drakrun@1
journalctl -e -u drakrun@1
```

## Project contents

The project is divided into two main packages:

* `drakcore*.deb` - system core, provides a web interface, an internal task queue and object storage
* `drakrun*.deb` - sandbox worker, should be installed where you want to run your Virtual Machines (Intel CPU with VT-x and EPT is required)

Please note that the [DRAKVUF engine](https://github.com/tklengyel/drakvuf) is a separate project authored by Tamas K Lengyel.

### Sandbox Core

The system core package `drakcore*.deb` consists of the following services:

* `drak-web` - web interface that allows user to interact with the sandbox
* `drak-system` - internal task management system, using for dispatching jobs between workers
* `drak-minio` - builtin object storage on which analysis results are stored

### Sandbox Worker

A worker package `drakrun*.deb` is basically a wrapper around DRAKVUF project that spins off `drakrun` service instances. These instances are processing the queued suspicious files one after another, using appropriate infrastructure. This component also features a `draksetup` command that makes it easier to setup configuration that is necessary to run services.

## Maintainers/authors

Feel free to contact us if you have any questions or comments.

* Michał Leszczyński - monk@cert.pl
* Adam Kliś - bonus@cert.pl
* Hubert Jasudowicz - chivay@cert.pl

If you have any questions about [DRAKVUF](https://drakvuf.com/) engine itself, contact tamas@tklengyel.com

## CEF Notice

![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/wp-content/uploads/2019/02/en_horizontal_cef_logo-1.png)
