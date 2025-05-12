
=================
Optional features
=================


This sections contains various information about optional features that may be enabled when setting up DRAKVUF Sandbox.


.. _zfs-backend:

ZFS storage backend
-------------------
If you want to install DRAKVUF Sandbox with a ZFS storage backend, you should perform the following extra steps before executing ``draksetup install`` command:

1. Install ZFS on your machine (guide for: `Debian Buster <https://github.com/openzfs/zfs/wiki/Debian>`_, `Ubuntu 18.04 <https://ubuntu.com/tutorials/setup-zfs-storage-pool#2-installing-zfs>`_)
2. Create a ZFS pool on a free partition:

   .. code-block:: console

     # zpool create tank <partition_name>

   where ``<partiton_name>`` is e.g. ``/dev/sda3``. Be aware that all data stored on the selected partition may be erased.

3. Create a dataset for DRAKVUF Sandbox:

   .. code-block:: console
   
     # zfs create tank/vms

4. Execute ``draksetup install`` as in "Basic installation" section, but remembering to provide additional command line switches:

   .. code-block:: console

     --storage-backend zfs --zfs-tank-name tank/vms

Networking
----------

.. note ::
  Even though that the guest Internet connectivity is an optional feature, ``drakrun`` would always make some changes to your host system's network configuration:

Always:

* Each instance of ``drakrun@<vm_id>`` will create a bridge ``drak<vm_id>``, assign ``10.13.<vm_id>.1/24`` IP address/subnet to it and bring the interface up.
* ``drakrun`` will drop any INPUT traffic originating from ``drak<vm_id>`` bridge, except DHCP traffic (UDP ports: 67, 68).

Only with ``net_enable=1``:

* ``drakrun`` will enable IPv4 forwarding.
* ``drakrun`` will configure MASQUERADE through ``out_interface`` for packets originating from ``10.13.<vm_id>.0/24``.
* ``drakrun`` will DROP traffic between ``drak<X>`` and ``drak<Y>`` bridges for ``X != Y``.

In order to find out the exact details of the network configuration, search for ``_add_iptable_rule`` function usages in ``drakrun/drakrun/main.py`` file.

Basic networking
~~~~~~~~~~~~~~~~

If you want your guest VMs to access Internet, you can enable networking by editing ``[drakrun]``
section in ``/etc/drakrun/config.ini``:

* Set ``net_enable=1`` in order to enable guest Internet access.
* Check if ``out_interface`` was detected properly (e.g. ``ens33``) and if not, correct this setting.

After making changes to ``/etc/drakrun``, you need to restart all ``drakrun`` services that are running
in your system:

.. code-block:: console 

  # systemctl restart 'drakrun@*'

Be aware that if your sandbox instance is already running some analyses, the above command will gracefully
wait up to a few minutes until these are completed.

Using dnschef
~~~~~~~~~~~~~

You may optionally configure your guests to use dnschef.

1. Setup `dnschef <https://github.com/iphelix/dnschef>`_ tool.
2. Start ``dnschef`` in such way to make it listen on all ``drak*`` interfaces that belong to DRAKVUF Sandbox.
3. Set ``dns_server=use-gateway-address`` in ``/etc/drakrun/config.ini``.
4. Restart your drakrun instances: ``systemctl restart 'drakrun@*``.

MS Office file support
----------------------

There is an experimental support for analyzing word and excel samples. However this requires that you have Microsoft Office installed.

The steps below should be completed on guest vm before creating the snapshot (e.g. before you run ``drakrun postinstall``).
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

ProcDOT integration
-------------------
DRAKVUF Sandbox may optionally draw a behavioral graph using `ProcDOT <https://www.procdot.com/>`_, if ``drakcore`` will find it's binary installed at ``/opt/procdot/procmon2dot``.

1. `Download ProcDOT <https://www.procdot.com/downloadprocdotbinaries.htm>`_ (Linux version).
2. With your downloaded ``procdot*_linux.zip`` archive, execute the following commands:

  .. code-block :: console

   # unzip -o procdot*_linux.zip lin64/* -d /tmp/procdot
   # mv /tmp/procdot/lin64 /opt/procdot
   # chmod +x /opt/procdot/procmon2dot

3. Your new analysis reports will also contain behavioral graphs.
