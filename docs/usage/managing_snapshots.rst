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
