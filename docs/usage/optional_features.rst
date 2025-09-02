
=================
Optional features
=================

This sections contains various information about optional features that may be enabled when setting up DRAKVUF Sandbox.

.. _s3-integration:

S3 integration
--------------

DRAKVUF Sandbox can use S3 bucket as a primary storage for your analyses.

You can configure it by adding ``[s3]`` section to the ``/etc/drakrun/config.toml`` configuration file.

.. code-block:: toml

  [s3]
  address = "https://<your-s3-host>"
  access_key = "<your access key>"
  secret_key = "<your secret key>"
  bucket = "drakrun"

When you configure S3, new analyses will be uploaded to the S3 and served from it by the web application.
Locally stored analyses will not be available. If you already made some, you need to migrate them using the following one-liner:

.. code-block:: console

  $ for f in /var/lib/drakrun/analyses/*; do drakrun s3 export $(basename $f); done

.. _zfs-backend:

ZFS storage backend
-------------------
If you want to install DRAKVUF Sandbox with a ZFS storage backend, you should perform the following extra steps before executing ``drakrun install`` command:

1. Install ZFS on your machine (guide for: `Debian Buster <https://github.com/openzfs/zfs/wiki/Debian>`_, `Ubuntu 18.04 <https://ubuntu.com/tutorials/setup-zfs-storage-pool#2-installing-zfs>`_)
2. Create a ZFS pool on a free partition:

   .. code-block:: console

     # zpool create tank <partition_name>

   where ``<partiton_name>`` is e.g. ``/dev/sda3``. Be aware that all data stored on the selected partition may be erased.

3. Create a dataset for DRAKVUF Sandbox:

   .. code-block:: console
   
     # zfs create tank/vms

4. Execute ``drakrun install`` as in "Basic installation" section, but remembering to provide additional command line switches:

   .. code-block:: console

     --storage-backend zfs --zfs-tank-name tank/vms

CLI analysis
------------

Starting from v0.19.0, you can run analysis directly from CLI without need to configure the UI and RQ worker.

You don't even have to provide a sample to run. It's particularly useful if you just want to record the regular VM activity
and check if your snapshot is configured correctly and doesn't generate too much noise. You can also provide
``--no-restore`` flag to handle the VM lifecycle manually using ``vm-start/vm-stop`` commands.

.. code-block:: console

  Usage: drakrun analyze [OPTIONS]

    Run a CLI analysis using Drakvuf

  Options:
    --vm-id INTEGER               VM id to use for analysis  [default: 1]
    --output-dir PATH             Output directory for analysis (default is
                                  analysis_<timestamp>)
    --sample PATH                 Sample to inject and execute (if not provided,
                                  assumes that executable will be executed
                                  manually)
    --timeout INTEGER             Analysis timeout (default is None, analysis
                                  interrupted on CTRL-C)
    --preset TEXT                 Use specified defaults preset from
                                  configuration
    --target-filename TEXT        Target file name where sample will be copied
                                  on a VM
    --start-command TEXT          Start command to use for sample execution
    --plugin TEXT                 Plugin name to use instead of default list
                                  (you can provide multiple ones)
    --net-enable / --net-disable  Enable/disable Internet access for analysis
    --no-restore                  Don't restore VM for analysis (assume it's
                                  already running)
    --no-post-restore             Don't run a post-restore script
    --no-screenshotter            Don't make screenshots during analysis
    --help                        Show this message and exit.


Using "drakshell" command
-------------------------

DRAKVUF Sandbox during VM profiling injects a small shellcode agent called "drakshell" that is injected into ``explorer.exe``
and assists in VM preparation. The analysis process itself is still agentless - drakshell is terminated and removes itself
from the memory before malware sample is executed. Agent communicates with Dom0 over serial port and allows to interactively e
xecute arbitrary commands.

We can use drakshell to spawn an interactive shell directly:

.. code-block:: console

  $ drakrun vm-start
  ...
  $ drakrun drakshell -- cmd.exe

  [2025-07-22 17:17:41,008][INFO] Drakshell active on: {'pid': 2280, 'tid': 5624}
  Microsoft Windows [Version 10.0.19045.5854]
  (c) Microsoft Corporation. All rights reserved.

  C:\Windows\system32>

DRAKVUF Sandbox is able to work without drakshell and use only pure VMI for preparation commands but this approach is
usually not stable.

DRAKVUF comes with an "injector" that is able to inject arbitrary code into any running thread in the guest VM. DRAKVUF
Sandbox heavily relies on that feature injecting various guest operations into "explorer.exe".
The problem is that the hijacked thread must be scheduled multiple times by the OS to complete the operation, so if we
have bad luck, the thread may be terminated prematurely or stuck in waiting state so the injection will fail.

To solve this: drakshell calls blocking WinAPI functions with a short timeout, making its thread a very good target
for injection.

Using "injector" command
------------------------

Another utility provided by drakrun CLI is "injector" which uses the DRAKVUF injector feature to copy files
between VM and host and create processes.

.. code-block:: console

   Usage: drakrun injector [OPTIONS] COMMAND [ARGS]...

    Copy files and execute commands on VM using injector

  Options:
    --help  Show this message and exit.

  Commands:
    copy  Copy files between VM and host
    exec  Execute commands on VM using injector (non-interactive)

If you want to copy the ``C:\Windows\System32\ntdll.dll`` from vm-1 to the local directory, run:

.. code-block:: console

  $ drakrun injector copy vm-1:"C:/Windows/System32/ntdll.dll" .
  {"Plugin": "inject", "TimeStamp": "1753205094.187867", "Method": "ReadFile", "Status": "Success", "ProcessName": "C:\\Windows\\System32\\ntdll.dll", "Arguments": "", "InjectedPid": 0, "InjectedTid": 0}

Windows environment variables are expanded, so if you want to copy it back to the Desktop of the current user, you can run:

.. code-block:: console

  $ drakrun injector copy ./ntdll.dll vm-1:"%USERPROFILE%/Desktop/ntdll.dll"
  {"Plugin": "inject", "TimeStamp": "1753205197.885914", "Method": "WriteFile", "Status": "Success", "ProcessName": "C:\\Users\\user\\Desktop\\ntdll.dll", "Arguments": "", "InjectedPid": 0, "InjectedTid": 0}

If you want to start a new process, use ``exec`` command:

.. code-block:: console

  $ drakrun injector exec calc.exe
  DRAKVUF injector v1.1-9833fa5 Copyright (C) 2014-2024 Tamas K Lengyel
  {"Plugin": "inject", "TimeStamp": "1753205233.513920", "Method": "CreateProc", "Status": "Success", "ProcessName": "calc.exe", "Arguments": "", "InjectedPid": 1428, "InjectedTid": 5648}


Spawning Drakvuf engine manually
--------------------------------

Sometimes during debug or development we may want to run DRAKVUF engine directly. DRAKVUF commands are quite lengthy and
that's why DRAKVUF Sandbox CLI comes with simple utility that prints the DRAKVUF command with base arguments on standard output.

.. code-block:: console

  $ drakrun drakvuf-cmdline
  drakvuf -o json -F -k 0x1aa002 -r /var/lib/drakrun/profiles/kernel.json -d vm-1 --json-ntdll /var/lib/drakrun/profiles/native_ntdll_profile.json --json-wow /var/lib/drakrun/profiles/wow64_ntdll_profile.json --json-win32k /var/lib/drakrun/profiles/native_win32k_profile.json --json-kernel32 /var/lib/drakrun/profiles/native_kernel32_profile.json --json-wow-kernel32 /var/lib/drakrun/profiles/wow64_kernel32_profile.json --json-tcpip /var/lib/drakrun/profiles/native_tcpip_profile.json --json-sspicli /var/lib/drakrun/profiles/native_sspicli_profile.json --json-kernelbase /var/lib/drakrun/profiles/native_kernelbase_profile.json --json-iphlpapi /var/lib/drakrun/profiles/native_iphlpapi_profile.json --json-mpr /var/lib/drakrun/profiles/native_mpr_profile.json --json-clr /var/lib/drakrun/profiles/native_clr_profile.json --json-mscorwks /var/lib/drakrun/profiles/native_mscorwks_profile.json

We can easily use it to launch DRAKVUF with "procmon" plugin to test if it works:

.. code-block:: console

  $ $(drakrun drakvuf-cmdline) -a procmon
  1753206195.266065 DRAKVUF v1.1-9833fa5 Copyright (C) 2014-2024 Tamas K Lengyel
  {"Plugin":"procmon","TimeStamp":"1753206195.453337","PID":4,"PPID":0,"RunningProcess":"System","Bitness":64}
  {"Plugin":"procmon","TimeStamp":"1753206195.453543","PID":92,"PPID":4,"RunningProcess":"Registry","Bitness":64}
  ...

Networking
----------

.. note ::
  Even though that the guest Internet connectivity is an optional feature, ``drakrun`` would always make some changes to your host system's network configuration:

Always:

* Each instance of ``drakrun-worker@<vm_id>`` will create a bridge ``drak<vm_id>``, assign ``10.13.<vm_id>.1/24`` IP address/subnet to it and bring the interface up.
* ``drakrun`` will drop any INPUT traffic originating from ``drak<vm_id>`` bridge, except DHCP traffic (UDP ports: 67, 68).

Only with ``net_enable = true``:

* ``drakrun`` will enable IPv4 forwarding.
* ``drakrun`` will configure MASQUERADE through ``out_interface`` for packets originating from ``10.13.<vm_id>.0/24``.
* ``drakrun`` will DROP traffic between ``drak<X>`` and ``drak<Y>`` bridges for ``X != Y``.

In order to find out the exact details of the network configuration, search for ``_add_iptable_rule`` function usages in ``drakrun/drakrun/main.py`` file.

Basic networking
~~~~~~~~~~~~~~~~

If you want your guest VMs to access Internet, set ``net_enable = true`` in ``[network]`` section of
``/etc/drakrun/config.toml`` file to enable guest Internet access.

After making changes to ``/etc/drakrun``, you need to restart all ``drakrun-worker`` services that are running
in your system:

.. code-block:: console 

  # systemctl restart 'drakrun-worker@*'

Be aware that if your sandbox instance is already running some analyses, the above command will gracefully
wait up to a few minutes until these are completed.

Using dnschef
~~~~~~~~~~~~~

You may optionally configure your guests to use dnschef.

1. Setup `dnschef <https://github.com/iphelix/dnschef>`_ tool.
2. Start ``dnschef`` in such way to make it listen on all ``drak*`` interfaces that belong to DRAKVUF Sandbox.
3. Set ``dns_server = "use-gateway-address"`` in ``/etc/drakrun/config.toml``.
4. Restart your drakrun instances: ``systemctl restart 'drakrun-worker@*'``.

MS Office file support
----------------------

There is an experimental support for analyzing word and excel samples. However this requires that you have Microsoft Office installed.

The steps below should be completed on guest vm before creating the snapshot (e.g. before you run ``draksetup postinstall``).
If you want to modify the existing snapshot, please refer to :ref:`snapshot modification <snapshot-modification>`.

1. Install Microsoft Office. You can use ``draksetup mount /path/to/office.iso`` command to insert Office installation media during VM setup.
   After installation, you should be able to start word/excel by running ``start winword.exe``, ``start excel.exe`` from command line.
2. Adjust the registry keys by executing this `.reg` file:

   .. code-block:: console

     Windows Registry Editor Version 5.00

     [HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\Word\Security]
     "VBAWarnings"=dword:00000001
     "AccessVBOM"=dword:00000001
     "ExtensionHardening"=dword:00000000

     [HKEY_CURRENT_USER\Software\Microsoft\Office\14.0\Excel\Security]
     "VBAWarnings"=dword:00000001
     "AccessVBOM"=dword:00000001
     "ExtensionHardening"=dword:00000000

   (change 14.0 to your Office version, see `registry key by product name <https://docs.microsoft.com/en-us/office/troubleshoot/word/reset-options-and-settings-in-word#word-key>`_)
