===============
Getting started
===============

Supported hardware & software
=============================

In order to run DRAKVUF Sandbox, your setup must fullfill all of the listed requirements:

* Processor: Intel processor with VT-x and EPT features (:ref:`how to check <check-cpu>`).
* Host system: Debian 10 Buster/Ubuntu 18.04 Bionic/Ubuntu 20.04 Focal with at least 2 core CPU and 5 GB RAM, running GRUB as bootloader.
* Guest system: Windows 7 (x64), Windows 10 (x64; experimental support)

Nested virtualization:

* KVM **does** work, however it is considered experimental. If you experience any bugs, please report them to us for further investigation.
* Due to lack of exposed CPU features, hosting DRAKVUF Sandbox in the cloud is **not** supported (although it might change in the future).
* Hyper-V does **not** work.
* Xen **does** work out of the box.
* VMware Workstation Player **does** work, but you need to check Virtualize EPT option for a VM; Intel processor with EPT still required.

Basic installation
==================

This instruction assumes that you want to create a single-node installation with the default components, which is recommended for beginners.

1. Download `latest release packages <https://github.com/CERT-Polska/drakvuf-sandbox/releases>`_.
2. Install DRAKVUF:

    .. code-block:: console

      # apt update
      # apt install ./drakvuf-bundle*.deb
      # reboot
3. Install DRAKVUF Sandbox stack:

    .. code-block:: console
    
      # apt install redis-server
      # apt install ./drakcore*.deb
      # apt install ./drakrun*.deb
4. Execute:

    .. code-block:: console

      # draksetup install /opt/path_to_windows.iso

   Read the command's output carefully. This command will run a virtual machine with Windows system installation process.
   
   **Unattended installation:** If you have ``autounattend.xml`` matching your Windows ISO, you can request unattended installation by adding ``--unattended-xml /path/to/autounattend.xml``. Unattended install configuration can be generated with `Windows Answer File Generator <https://www.windowsafg.com/win10x86_x64.html>`_.
   
  .. note::
   By default, DRAKVUF Sandbox will store virtual machine's HDD in a ``qcow2`` file. If you want to use ZFS instead, please check the :ref:`ZFS storage backend<zfs-backend>` docs.

5. Use VNC to connect to the installation process:

    .. code-block:: console

      $ vncviewer localhost:5900

6. Perform Windows installation until you are booted to the desktop.

7. **Optional:** At this point you might optionally install additional software. You can execute:

    .. code-block:: console

      # draksetup mount /path/to/some-cd.iso

   which would mount a virtual CD disk containing additional software into your VM.

8. **Optional:** Generate .NET Framework native image cache by executing the following commands in the administrative prompt of your VM.

    .. code-block:: bat

      cd C:\Windows\Microsoft.NET\Framework\v4.0.30319
      ngen.exe executeQueuedItems
      cd C:\Windows\Microsoft.NET\Framework64\v4.0.30319
      ngen.exe executeQueuedItems

9. In order to finalize the VM setup process, execute:

  .. code-block:: console

    # draksetup postinstall

  .. note ::
    Add ``--no-report`` if you don't want ``draksetup`` to send `basic usage report <https://github.com/CERT-Polska/drakvuf-sandbox/blob/master/USAGE_STATISTICS.md>`_. 

10. Test your installation by navigating to the web interface ( http://localhost:6300/ ) and uploading some samples. The default analysis time is 10 minutes.
