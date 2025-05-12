===============
Getting started
===============

Supported hardware & software
=============================

In order to run DRAKVUF Sandbox, your setup must fullfill all of the listed requirements:

* Processor: Intel processor with VT-x and EPT features (:ref:`how to check <check-cpu>`).
* Host system: Debian 11 Bullseye/Ubuntu 20.04 Focal with at least 2 core CPU and 5 GB RAM, running GRUB as bootloader.
* Guest system: Windows 7 (x64), Windows 10 (x64; experimental support)

DRAKVUF Sandbox toolkit is based on `Karton project <https://karton-core.readthedocs.io/en/latest/>`_ so it also requires:

* Redis server
* S3 object storage, most recommended is `MinIO <https://min.io/>`_

Nested virtualization:

* KVM **does** work, however it is considered experimental. If you experience any bugs, please report them to us for further investigation.
* Due to lack of exposed CPU features, hosting DRAKVUF Sandbox in the cloud is **not** supported (although it might change in the future).
* Hyper-V does **not** work.
* Xen **does** work out of the box.
* VMware Workstation Player **does** work, but you need to check Virtualize EPT option for a VM; Intel processor with EPT still required.

.. _basic_installation:

Basic installation
==================

This instruction assumes that you want to create a single-node installation with the default components, which is recommended for beginners.

It's also recommended to perform all installation activities using ``root`` user.

**Step 1. Installation of DRAKVUF engine and basic dependencies**

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

    # drakrun postinstall

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
