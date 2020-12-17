==================
Managing snapshots
==================

Current sandbox implemention allows for a single VM snapshot installed on a machine.
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
