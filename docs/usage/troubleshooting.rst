Troubleshooting
===============

Checking service status
-----------------------

If your DRAKVUF Sandbox installation seems to work improperly, here are some commands that would help to troubleshoot the infrastructure.

Check service status:

.. code-block:: console

  # drak-healthcheck

Check service logs:

.. code-block:: console

  # journalctl -e -u drak-web
  # journalctl -e -u drak-system
  # journalctl -e -u drak-minio
  # journalctl -e -u drak-postprocess@1
  # journalctl -e -u drakrun@1

Debug ``device model did not start``
------------------------------------

You may encounter the following error with ``draksetup`` command or ``drakrun@*`` service, which will prevent the VM from starting properly.

::

    libxl: error: libxl_create.c:1676:domcreate_devmodel_started: Domain 4:device model did not start: -3
    ...
    subprocess.CalledProcessError: Command 'xl create /etc/drakrun/configs/vm-0.cfg' returned non-zero exit status 3.

In such a case, you should inspect ``/var/log/xen/qemu*.log`` in order to determine the actual reason why the VM is refusing to start.

Debug ``can't allocate low memory for domain``
----------------------------------------------

The following error with ``draksetup`` command or ``drakrun@*`` service means that your machine is missing memory resources:

::

    xc: error: panic: xc_dom_boot.c:122: xc_dom_boot_mem_init: can't allocate low memory for domain: Out of memory
    ...
    subprocess.CalledProcessError: Command 'xl create /etc/drakrun/configs/vm-0.cfg' returned non-zero exit status 3.

Resolutions:

* adjust the amount of memory dedicated to the Dom0 (host system) in ``/etc/default/grub.d/xen.cfg`` (look for ``dom0_mem=2048M,max:2048M``) and run ``update-grub && reboot``
* adjust the amount of memory dedicated to the DomU (guest systems) in ``/etc/drakrun/scripts/cfg.template`` (``maxmem`` and ``memory`` keys)
