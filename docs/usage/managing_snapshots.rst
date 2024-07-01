==================
Managing snapshots
==================

.. _snapshot-modification:

Snapshot modification
=====================

Before trying to modify the installation, make sure that all ``drakrun@`` services are stopped.

Execute ``drakplayground 0`` as root. Output of the command should look similarly to this:

.. code-block:: ipython

    dnsmasq: started, version 2.83 DNS disabled
    dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset auth nettlehash DNSSEC loop-detect inotify dumpfile
    dnsmasq-dhcp: DHCP, IP range 10.13.0.100 -- 10.13.0.200, lease time 12h
    dnsmasq-dhcp: DHCP, sockets bound exclusively to interface drak0
    Loading new save file /var/lib/drakrun/volumes/snapshot.sav (new xl fmt info 0x3/0x0/2015)
     Savefile contains xl domain config in JSON format
    Parsing config from /etc/drakrun/configs/vm-0.cfg
    xc: info: Found x86 HVM domain from Xen 4.15
    xc: info: Restoring domain
    xc: info: Restore successful
    xc: info: XenStore: mfn 0xfeffc, dom 0, evt 1
    xc: info: Console: mfn 0xfefff, dom 0, evt 2

    *** Welcome to drakrun playground ***
    Your VM is now ready and running with internet connection.
    You can connect to it using VNC (password can be found in /etc/drakrun/scripts/cfg.template)
    Run help() to list available commands.

    In [1]:

You will be dropped into a IPython shell, with vm-0 running and internet connection configured.
At this point you can connect to VNC and perform the modifications. **Don't exit** the shell or
close the terminal.

If you have some scripts, executables or other files on the host, you can copy them into the VM
with a helper function:

.. code-block:: ipython

    In [1]: copy("/root/examples/example1.exe")

Copied files should appear on the desktop.

When you're done, open another terminal window and execute ``draksetup postinstall``. The command
will recreate the snapshot and profiles for other virtual machines.

It is now safe to close the shell. To do this execute:

.. code-block:: ipython

    In [10]: exit()

or hit Ctrl+D.

.. warning::
    vm-0 is a base for other virtual machines. Leaving it in a broken or inconsistent state will
    result in analysis failures, BSODs and other unexpected errors. When modifying the vm-0 always
    make sure to perform the postinstall step.


Importing and exporting snapshots
=================================

Current sandbox implementation allows for a single VM snapshot installed on a machine.
However, it is possible to export and import snapshots from a remote server.

This is especially useful when running drakrun on multiple machines that should share same snapshot.

There are two types of snapshots: minimal and full.
Before doing anything you should know which is appropriate for your usecase.

Minimal snapshot
----------------

Minimal snapshot contains only the most essential parts of the virtual machine
which include HDD image and VM configuration.

This has both some advantages and drawbacks:

* before using the snapshot on a new machine, VM must be cold booted to the desktop
  and ``draksetup postinstall`` must be executed to extract runtime information,
* this snapshot type is more portable and stable as the operating system is being booted
  on the hardware that will be used for performing analyses.

.. note::
    Starting minimal VM may trigger operating system checks for a dirty filesystem.
    This shouldn't cause any issues after configuring the snapshot.

Full snapshot
-------------

Full snapshots contain all of the data required by ``drakrun`` to work correctly.
Apart from configuration and disk images they also contain compressed dumps of the
VM's physical memory and runtime information.

After importing a full snapshot no additional steps are required.

.. warning::
    Full snapshots are tightly coupled with the hardware they were generated on.
    Importing incompatible snapshot may result in unexpected behavior ranging from
    failures to create virtual machies, to guest crashes.

    When in doubt use minimal snapshots
