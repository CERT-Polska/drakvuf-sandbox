===============
Getting started
===============

Supported hardware & software
=============================

In order to run DRAKVUF Sandbox, your setup must fulfill all of the listed requirements:

* Processor: Intel processor with VT-x and EPT features (:ref:`how to check <check-cpu>`).
* Host system: Debian 12 Bookworm/Ubuntu 22.04 (Jammy Jellyfish) with at least 2 core CPU and 8 GB RAM, running GRUB as bootloader.
* Host linux kernel version: 5.11+ recommended
* Guest system: Windows 10 (x64, 22H2 recommended), Windows 7 (x64)
* Hypervisor: Xen (at least 4.17, 4.19 recommended)

Nested virtualization:

* KVM **does** work, however it is considered experimental. If you experience any bugs, please report them to us for further investigation.
* Due to lack of exposed CPU features, hosting DRAKVUF Sandbox in the cloud is **not** supported (although it might change in the future).
* Hyper-V does **not** work.
* Xen **does** work out of the box.
* VMware Workstation Player **does** work, but you need to check Virtualize EPT option for a VM; Intel processor with EPT still required.

.. _basic_installation:

First steps: Basic installation
===============================

**Step 1. Installation of Xen Hypervisor and DRAKVUF engine**

First you need to perform Xen installation and install DRAKVUF engine itself. Official DRAKVUF installation instruction can be found on https://drakvuf.com/

It's recommended to build components from sources to include latest patches that may be crucial for the stability of the system.

* Xen 4.19.2 sources: https://downloads.xenproject.org/release/xen/4.19.2/
* Drakvuf sources: https://github.com/tklengyel/drakvuf

Perform the Xen and DRAKVUF installation without installing Windows domain and creating JSON profiles. DRAKVUF Sandbox toolkit will assist you in creating
the snapshot and its VMI profile. DRAKVUF Sandbox requires the following LibVMI/DRAKVUF CLI commands to be available in your PATH:

* ``drakvuf``
* ``injector``
* ``vmi-win-guid``
* ``vmi-win-offsets``
* ``vmi-process-list``

It's required to perform all installation activities using ``root`` user.

Below you can find the installation instruction that we've followed and it's working on fresh Debian 12 installation:

First, install build dependencies and unpack Xen 4.19.2 sources

.. code-block:: console

    $ apt update
    $ apt-get install wget git bcc bin86 gawk bridge-utils iproute2 libcurl4-openssl-dev bzip2 libpci-dev build-essential make gcc clang libc6-dev linux-libc-dev zlib1g-dev libncurses5-dev patch libvncserver-dev libssl-dev libsdl1.2-dev iasl libbz2-dev e2fslibs-dev git-core uuid-dev ocaml libx11-dev bison flex ocaml-findlib xz-utils gettext libyajl-dev libpixman-1-dev libaio-dev libfdt-dev cabextract libglib2.0-dev autoconf automake libtool libjson-c-dev libfuse-dev liblzma-dev autoconf-archive kpartx python3-dev python3-pip golang libsystemd-dev nasm ninja-build llvm lld meson

    $ cd /opt
    $ wget https://downloads.xenproject.org/release/xen/4.19.2/xen-4.19.2.tar.gz
    $ tar -xvzf xen-4.19.2.tar.gz
    $ cd xen-4.19.2

Note from 2025-04-24: Xen refers to old Tianocore OVMF version that refers to broken subhook submodule URL (https://github.com/tianocore/edk2/commit/4dfdca63a93497203f197ec98ba20e2327e4afe4)

To overcome this issue, we changed the OVMF version to edk2-stable202408.01 by applying this patch to Config.mk:

.. code-block:: diff
   - OVMF_UPSTREAM_URL ?= https://xenbits.xen.org/git-http/ovmf.git
   - OVMF_UPSTREAM_REVISION ?= ba91d0292e593df8528b66f99c1b0b14fadc8e16
   + OVMF_UPSTREAM_URL ?= https://github.com/tianocore/edk2.git
   + OVMF_UPSTREAM_REVISION ?= 4dfdca63a93497203f197ec98ba20e2327e4afe4

Then build and install Xen:

.. code-block:: console
    $ chmod +x ./configure
    $ ./configure --enable-githttp --enable-systemd --enable-ovmf --disable-pvshim
    $ make -j4 dist-xen
    $ make -j4 dist-tools
    $ make -j4 debball
    $ apt install ./dist/xen-upstream-4.19.2.deb

Then set default Xen cmdline to run Xen with Dom0 getting 4GB RAM assigned and two dedicated CPU cores (tune it as preferred):

.. code-block:: console

    $ echo "GRUB_CMDLINE_XEN_DEFAULT=\"dom0_mem=4096M,max:4096M dom0_max_vcpus=2 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0\"" >> /etc/default/grub
    $ echo "/usr/local/lib" > /etc/ld.so.conf.d/xen.conf
    $ ldconfig

Then enable necessary Xen modules, update GRUB and reboot system to Xen

.. code-block:: console

    $ echo "none /proc/xen xenfs defaults,nofail 0 0" >> /etc/fstab
    $ echo "xen-evtchn" >> /etc/modules
    $ echo "xen-privcmd" >> /etc/modules
    $ echo "xen-gntdev" >> /etc/modules
    $ systemctl enable xencommons.service
    $ systemctl enable xen-qemu-dom0-disk-backend.service
    $ systemctl enable xen-init-dom0.service
    $ systemctl enable xenconsoled.service
    $ update-grub
    $ reboot

Once you are booted into Xen, verify that everything works as such:

.. code-block:: console

    $ xen-detect

    Running in PV context on Xen V4.19.

    $ xl list

    Name                                        ID   Mem VCPUs	State	Time(s)
    Domain-0                                     0  4096     2     r-----       6.9

Since your Xen installation is ready, install Drakvuf engine, starting from installation of LibVMI:

.. code-block:: console

    $ git clone --recursive https://github.com/tklengyel/drakvuf
    $ cd drakvuf/libvmi
    $ autoreconf -vif
    $ ./configure --disable-kvm --disable-bareflank --disable-file
    $ make
    $ make install
    $ echo "export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/usr/local/lib" >> ~/.bashrc
    $ export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    $ ldconfig

Check if ``vmi-win-guid`` command loads correctly

.. code-block:: console

    $ vmi-win-guid
    Usage: vmi-win-guid name|domid <domain name|domain id> [<socket>]

Then install DRAKVUF itself:

.. code-block:: console

    $ cd /opt/drakvuf
    $ meson setup build --native-file llvm.ini
    $ ninja -C build
    $ mv build/drakvuf build/injector /usr/local/bin/

Check if ``drakvuf`` and ``injector`` commands load correctly:

.. code-block:: console

    $ drakvuf
    1745511832.661881 DRAKVUF v1.1-f46a733 Copyright (C) 2014-2024 Tamas K Lengyel
    No domain name specified (-d)!

    $ injector
    DRAKVUF injector v1.1-f46a733 Copyright (C) 2014-2024 Tamas K Lengyel
    Required input:
      ... (truncated help message)

**Step 2. Installation of DRAKVUF Sandbox**

1. Install additional DRAKVUF Sandbox dependencies

.. code-block:: console

    $ apt update
    $ apt install iptables tcpdump dnsmasq qemu-utils bridge-utils libmagic1 python3-venv redis-server

2. Prepare virtualenv

.. code-block:: console

    $ cd /opt
    $ python3 -m venv venv
    $ . venv/bin/activate
    $ pip install wheel

3. Install DRAKVUF Sandbox package

.. code-block:: console
    $ pip install drakvuf-sandbox

4. ``drakrun`` command should be available within created virtualenv

.. code-block:: console

    $ drakrun
    Usage: drakrun [OPTIONS] COMMAND [ARGS]...

    Options:
        --help  Show this message and exit.

    Commands:
        analyze          Run a CLI analysis using Drakvuf
        drakshell        Run drakshell session
        drakvuf-cmdline  Get base Drakvuf cmdline
        injector         Copy files and execute commands on VM using injector
        install          Install guest Virtual Machine
        make-profile     Make VMI profile
        modify-vm0       Modify base VM snapshot (vm-0)
        mount            Mount ISO into guest
        postinstall      Finalize VM installation
        postprocess      Run postprocessing on analysis output
        vm-start         Start VM from snapshot
        vm-stop          Stop VM and cleanup network
        worker           Start drakrun analysis worker

.. _creating_windows_vm:

Creating initial Windows VM snapshot
====================================

**Step 1: Initial Windows installation**

After all tools are installed correctly, we can proceed to actual VM installation. The command that start VM installation is ``drakrun install``.

.. code-block:: console

    $ drakrun install
    Usage: drakrun install [OPTIONS] ISO_PATH

    Install guest Virtual Machine

    Options:
      --vcpus INTEGER                 Number of vCPUs per single VM  [default: 2]
      --memory INTEGER                Memory per single VM (in MB)  [default:
                                      4096]
      --storage-backend [qcow2|zfs|lvm]
                                      Storage backend type  [default: qcow2]
      --disk-size TEXT                Disk size  [default: 100G]
      --zfs-tank-name TEXT            Tank name (only for ZFS storage backend)
      --lvm-volume-group TEXT         Volume group (only for lvm storage backend)
      --help                          Show this message and exit.

If you want to use defaults and qcow2 storage, download Windows installation ISO file into Dom0 and run:

.. code-block:: console
    $ drakrun install ./Win10_22H2.iso

.. note::

    If you have only 8GB RAM on your system, the default --memory 4096 setting may not fit in the memory
    and you'll see "RuntimeError: Failed to launch VM vm-0" with "can't allocate low memory for domain: Out of memory"
    message in the logs above it. In this case, provide a smaller value.

    If you are struggling with another type of error, check out the /var/log/xen directory for extra logs, especially
    these ending with vm-0.log.

This command will initialize all necessary configuration files and will create the template VM called **vm-0**.

Then proceed to Windows installation via VNC client connected to <ip>:5900, with password provided in the message.

Initial configuration turns off the Internet access for the VM to not be bothered with setting up a Microsoft account.
We will change that later.

.. note::

    **Troubleshooting**

    If you want to change or restore the VNC password, it is stored in plaintext in /etc/drakrun/install.json file.

    Your VNC connection will be terminated after the VM reboots. In this case, just reconnect the VNC client.

    If you can't, check if vm-0 is running using **xl list**. If you can't find it there, check the logs in /var/log/xen for possible errors.

    When you're ready to recover the VM: run ``xl create /var/lib/drakrun/configs/vm-0.cfg`` to cold boot the VM manually.

After finished installation, log in the user on Windows to the desktop.

**Step 2: Making initial snapshot and VMI profile**

When VM looks ready, we can make an initial snapshot. To do this, run ``drakrun postinstall``

.. code-block:: console
    $ drakrun postinstall

This command will:

* retrieve VMI kernel information
* inject drakshell helper agent
* take the reference snapshot (vm-0)
* restore the analysis VM (vm-1)
* retrieve VMI information from other system modules

Don't worry if you see "FileNotFoundError" in logs, we'll fix that in further steps.

.. _modifying_windows_vm:

Modifying Windows VM snapshot
=============================

Now, we have freshly installed Windows VM that is almost ready for analysis. In practice, such installation isn't
best environment for executing files because of missing dependencies, pending updates that will execute in
the background and so on.

That's why we want to make another, better reference snapshot. To do this, let's enable the Internet first.

To do this, change the line ``net_enable`` in ``/etc/drakrun/config.toml`` from "false" to "true".

Then we can use ``drakrun modify-vm0`` utility.

.. code-block:: console

    $ drakrun modify-vm0
    Usage: drakrun modify-vm0 [OPTIONS] COMMAND [ARGS]...

      Modify base VM snapshot (vm-0)

    Options:
      --help  Show this message and exit.

    Commands:
      begin     Safely restore vm-0 for modification
      commit    Commit changes made during vm-0 modification
      rollback  Rollback changes made during vm-0 modification

Let's use ``drakrun modify-vm0 begin`` for restoring the VM and connect once again to the 5900 port using VNC client.

.. code-block:: console

    $ drakrun modify-vm0 begin

At this point you might optionally install additional software. You can execute:

    .. code-block:: console

      $ drakrun mount /path/to/some-cd.iso

which would mount a virtual CD disk containing additional software into your VM.

Things that are highly recommended to do are:

* turn off the User Account Control <put link here>
* turn off the Windows Defender (be aware that it turns on automatically if you just switch it off in the Control Panel)
* run Powershell at least once to speed-up its execution
* install Visual C++ Redistributable in various versions <put link here>
* install .NET Framework in various versions
* generate .NET Framework native image cache e.g. by executing the following commands in the administrative prompt of your VM.

  .. code-block:: bat

      cd C:\Windows\Microsoft.NET\Framework\v4.0.30319
      ngen.exe executeQueuedItems
      cd C:\Windows\Microsoft.NET\Framework64\v4.0.30319
      ngen.exe executeQueuedItems

You can also install Xen PV drivers if you're experiencing performance issues (https://docs.xenserver.com/en-us/xenserver/8/vms/windows/vm-tools.html).
However, keep in mind that making such modifications can alter your environment, making it different from a typical user's setup.
This could potentially be exploited by malware as an indicator for sandbox detection.

If your VM is ready to go, run ``drakrun modify-vm0 commit``

.. code-block:: console

    $ drakrun modify-vm0 commit

It does similar thing as ``drakrun postinstall`` by safely applying your changes onto reference snapshot and recreating VM profile.

If you have any problems and you want to rollback VM to the pre-begin state, use ``rollback`` subcommand:

.. code-block:: console

    $ drakrun modify-vm0 rollback

.. note::

    If you want to cold-boot VM-0 that was spinned up via "modify-vm0 begin" e.g. after unexpected shutdown
    or other exceptional situation, you can use ``xl create /var/lib/drakrun/configs/vm-0.cfg`` to boot it up.

    These configuration files are generated on VM restore by drakrun.

Checking if Drakvuf works correctly
===================================

To ensure that everything works, use ``drakrun vm-start`` command to start the vm-1. You can also connect via VNC to the
port 5901 to check if the Windows is in correct state.

Then, run drakvuf tool with "procmon" plugin. Drakvuf Sandbox will help you do that by generating a base command-line.

.. code-block::

    $ drakrun drakvuf-cmdline
    drakvuf -o json -F -k 0x1aa002 -r /var/lib/drakrun/profiles/kernel.json -d vm-1 --json-ntdll /var/lib/drakrun/profiles/native_ntdll_profile.json --json-wow /var/lib/drakrun/profiles/wow64_ntdll_profile.json --json-win32k /var/lib/drakrun/profiles/native_win32k_profile.json --json-kernel32 /var/lib/drakrun/profiles/native_kernel32_profile.json --json-wow-kernel32 /var/lib/drakrun/profiles/wow64_kernel32_profile.json --json-tcpip /var/lib/drakrun/profiles/native_tcpip_profile.json --json-sspicli /var/lib/drakrun/profiles/native_sspicli_profile.json --json-kernelbase /var/lib/drakrun/profiles/native_kernelbase_profile.json --json-iphlpapi /var/lib/drakrun/profiles/native_iphlpapi_profile.json --json-mpr /var/lib/drakrun/profiles/native_mpr_profile.json --json-clr /var/lib/drakrun/profiles/native_clr_profile.json
    $ $(drakrun drakvuf-cmdline) -a procmon

After running the second command, you should see a stream of JSONs from "procmon" plugin. You can try to run new processes via VNC to check if Windows is responsive and you're correctly notified about new events.

If you finished, press CTRL-C to interrupt the Drakvuf trace and then destroy the VM using ``drakrun vm-stop`` command.

.. code-block::

    $ drakrun vm-stop

Setting up analysis queue and web UI
====================================

<<<<< CUT HERE >>>>>>


1. Download `latest release assets <https://github.com/CERT-Polska/drakvuf-sandbox/releases>`_.
2. Install DRAKVUF:

    .. code-block:: console

      $ apt update
      $ apt install ./drakvuf-bundle*.deb
      $ reboot

3. Install DRAKVUF Sandbox system dependencies

    .. code-block:: console
    
      $ apt install tcpdump genisoimage qemu-utils bridge-utils dnsmasq libmagic1

4. Install DRAKVUF Sandbox Python wheel. It's highly recommended to use `virtualenv <https://docs.python.org/3/library/venv.html>`_.

    .. code-block:: console

      $ python3 -m venv venv
      $ source venv/bin/activate
      $ pip install ./drakvuf_sandbox*.whl

5. Check if your Xen installation is compliant. This command should print "All tests passed":

    .. code-block:: console
    
      $ draksetup test

**Step 2. Redis, MinIO and Drakvuf Sandbox configuration**

6. Redis configuration can be done just by installing ``redis-server`` package from apt.

    .. code-block:: console

      $ apt install redis-server

7. For MinIO, we recommend to follow installation instructions in `MinIO documentation (Deploy: MinIO Single-Node Single-Drive) <https://min.io/docs/minio/linux/operations/install-deploy-manage/deploy-minio-single-node-single-drive.html>`_.

    If you're too busy to bother with MinIO installation or you just want to quickly setup Drakvuf Sandbox for testing/development, you can also use
    draksetup quick MinIO installer. Just keep in mind that it's not really recommended for production usage.

        .. code-block:: console

          $ draksetup install-minio

8. After setting up Redis and MinIO, you're finally ready to configure your DRAKVUF Sandbox installation using ``draksetup init``

    In the process, you'll be asked for Redis and MinIO connection details.

        .. code-block:: console

          $ draksetup init

          [2024-07-01 09:17:59,091][INFO] /etc/drakrun/config.ini already created.
          Provide redis hostname [...]:
          Provide redis port [...]:
          Provide S3 (MinIO) address [...]:
          Provide S3 (MinIO) access key [...]:
          Provide S3 (MinIO) secret key [...]:

    If your S3 storage uses secure (TLS) connection, run ``draksetup init --s3-secure``

9. Finally, review configuration file ``cat /etc/drakrun/config.ini`` and check if all settings are suitable for your environment

.. note::

    If you want to configure Drakvuf Sandbox to work with existing Karton configuration from the start,
    you can omit configuring ``drak-system`` service by running ``draksetup init`` with these flags:

    .. code-block:: console

        $ draksetup init --only web --only drakrun

**Step 3. Windows installation**

10. Execute:

    .. code-block:: console

      # draksetup install /opt/path_to_windows.iso

   Read the command's output carefully. This command will run a virtual machine with Windows system installation process.
   
   **Customize vCPUs/memory:** You can pass additional options in order to customize number of vCPUs (``--vcpus <number>``) and amount of memory (``--memory <num_mbytes>``) per single VM. For instance: ``--vcpus 1 --memory 2048``.
   
   *Recommended minimal values that are known to work properly with DRAKVUF Sandbox:*

   +-----------------+---------------+-------------+
   | System version  | Minimal vCPUs | Minimal RAM |
   +=================+===============+=============+
   | Windows 7       | 1             | 1536        |
   +-----------------+---------------+-------------+
   | Windows 10      | 2             | 3072        |
   +-----------------+---------------+-------------+
   
   **Unattended installation:** If you have ``autounattend.xml`` matching your Windows ISO, you can request unattended installation by adding ``--unattended-xml /path/to/autounattend.xml``. Unattended install configuration can be generated with `Windows Answer File Generator <https://www.windowsafg.com/win10x86_x64.html>`_.
   
  .. note::
   By default, DRAKVUF Sandbox will store virtual machine's HDD in a ``qcow2`` file. If you want to use ZFS instead, please check the :ref:`ZFS storage backend<zfs-backend>` docs.

11. Use VNC to connect to the installation process:

    .. code-block:: console

      $ vncviewer localhost:5900

12. Perform Windows installation until you are booted to the desktop.

13. **Optional:** At this point you might optionally install additional software. You can execute:

    .. code-block:: console

      # draksetup mount /path/to/some-cd.iso

   which would mount a virtual CD disk containing additional software into your VM.

14. **Optional:** Generate .NET Framework native image cache by executing the following commands in the administrative prompt of your VM.

    .. code-block:: bat

      cd C:\Windows\Microsoft.NET\Framework\v4.0.30319
      ngen.exe executeQueuedItems
      cd C:\Windows\Microsoft.NET\Framework64\v4.0.30319
      ngen.exe executeQueuedItems

15. In order to finalize the VM setup process, execute:

  .. code-block:: console

    # draksetup postinstall

  .. note ::
    Add ``--no-report`` if you don't want ``draksetup`` to send `basic usage report <https://github.com/CERT-Polska/drakvuf-sandbox/blob/master/USAGE_STATISTICS.md>`_. 

16. Test your installation by navigating to the web interface ( http://localhost:6300/ ) and uploading some samples. The default analysis time is 10 minutes.

Building from sources
=====================

1. Clone Drakvuf Sandbox repository including submodules

  .. code-block:: console

    $ git clone --recursive git@github.com:CERT-Polska/drakvuf-sandbox.git

2. Build and install Drakvuf from sources using `instructions from the official Drakvuf documentation <https://drakvuf.com/>`_. It's recommended to use version pinned to the submodule.

3. Install DRAKVUF Sandbox system dependencies

    .. code-block:: console

      $ apt install tcpdump genisoimage qemu-utils bridge-utils dnsmasq libmagic1

4. Install additional Web build dependencies

    .. code-block:: console

      $ apt install nodejs npm

5. Make and install DRAKVUF Sandbox Python wheel. It's highly recommended to use `virtualenv <https://docs.python.org/3/library/venv.html>`_.

    .. code-block:: console

      $ python3 -m venv venv
      $ source venv/bin/activate
      $ cd drakrun
      $ make
      $ make install

6. Follow the :ref:`Basic installation` starting from the Step 2. Redis, MinIO and Drakvuf Sandbox configuration.
