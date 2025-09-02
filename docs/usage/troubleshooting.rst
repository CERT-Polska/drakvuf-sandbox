Troubleshooting
===============

Debug ``device model did not start``
------------------------------------

You may encounter the following error with ``draksetup`` command or ``drakrun-worker@*`` service, which will prevent the VM from starting properly.

::

    libxl: error: libxl_create.c:1676:domcreate_devmodel_started: Domain 4:device model did not start: -3
    ...
    subprocess.CalledProcessError: Command 'xl create /etc/drakrun/configs/vm-0.cfg' returned non-zero exit status 3.

In such a case, you should inspect ``/var/log/xen/qemu*.log`` in order to determine the actual reason why the VM is refusing to start.

Debug ``can't allocate low memory for domain``
----------------------------------------------

The following error with ``drakrun`` command or ``drakrun-worker@*`` service means that your machine is missing memory resources:

::

    xc: error: panic: xc_dom_boot.c:122: xc_dom_boot_mem_init: can't allocate low memory for domain: Out of memory
    ...
    subprocess.CalledProcessError: Command 'xl create /var/lib/drakrun/configs/vm-0.cfg' returned non-zero exit status 3.

Resolutions:

* adjust the amount of memory dedicated to the Dom0 (host system) in ``/etc/default/grub.d/xen.cfg`` (look for ``dom0_mem=2048M,max:2048M``) and run ``update-grub && reboot``
* adjust the amount of memory dedicated to the DomU (guest systems) in ``/etc/drakrun/install.json`` or ``/etc/drakrun/cfg.template`` ( ``memory`` and ``maxmem`` keys)
