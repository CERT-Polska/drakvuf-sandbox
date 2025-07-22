==================
Managing snapshots
==================

.. _snapshot-modification:

Snapshot modification
=====================

modify-vm0 tool
---------------

Before trying to modify the installation, make sure that all ``drakrun@`` services are stopped and VMs are destroyed.

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

You can use ``drakrun snapshot`` command to import/export your VM disk image and memory snapshot.

.. code-block:: console

    $ drakrun snapshot
    Usage: drakrun snapshot [OPTIONS] COMMAND [ARGS]...

      Snapshot management commands (import/export)

    Options:
      --help  Show this message and exit.

    Commands:
      export  Export snapshot into local directory
      import  Import snapshot from local directory

``drakrun snapshot import`` accepts similar arguments as the ``drakrun install`` and can be used as an initial configuration command.

When snapshot is imported onto different hardware configuration, it may throw an error when trying to restore the snapshot.
In that case, you may need to:

- cold boot your snapshot using ``drakrun modify-vm0 begin --cold-boot``
- wait for Windows to boot into Desktop
- use ``drakrun modify-vm0 commit`` to make a new VM-0 snapshot and regenerate VMI profile.
