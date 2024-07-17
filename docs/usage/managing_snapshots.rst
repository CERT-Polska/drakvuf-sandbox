==================
Managing snapshots
==================

.. _snapshot-modification:

Snapshot modification
=====================

modify-vm0 tool
---------------

Before trying to modify the installation, make sure that all ``drakrun@`` services are stopped.

Execute ``draksetup modify-vm0 begin`` as root. This will run vm-0 and at this point you can connect to VNC
and perform the modifications.

When you're done, open another terminal window and execute ``draksetup modify-vm0 commit``. The command
will recreate the snapshot and profiles for other virtual machines.

If modification doesn't go well and you want to rollback vm-0 to the state before modifications, run
``draksetup modify-vm0 rollback``.

.. warning::
    vm-0 is a base for other virtual machines. Leaving it in a broken or inconsistent state will
    result in analysis failures, BSODs and other unexpected errors. When modifying the vm-0 always
    make sure to perform the complete commit/rollback step.

Adding files to the VM snapshot
-------------------------------

During snapshot modification, you may want to install additional tools and programs on the guest.
To do that, after ``draksetup modify-vm0 begin``, execute ``drakplayground 0``.

Output of the command should look similarly to this:

.. code-block:: ipython

    *** Welcome to drakrun playground ***
    Your VM is now ready and running with internet connection.
    You can connect to it using VNC (password can be found in /etc/drakrun/scripts/cfg.template)
    Run help() to list available commands.

    In [1]:

You will be dropped into a IPython shell, with vm-0 running. At this point you can connect to
VNC and perform the modifications.

If you have some scripts, executables or other files on the host, you can copy them into the VM
with a helper function:

.. code-block:: ipython

    In [1]: copy("/root/examples/example1.exe")

Copied files should appear on the desktop.

It is now safe to close the shell. To do this execute:

.. code-block:: ipython

    In [10]: exit()

or hit Ctrl+D.

After that, use ``draksetup modify-vm0 commit`` to apply your changes to the main vm-0 snapshot.

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
