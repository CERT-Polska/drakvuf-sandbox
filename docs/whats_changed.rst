===============================
What's changed, how to upgrade?
===============================

v0.21.0
-------

This release comes with multiple bugfixes and additional web application features.

Most important changes:

- Web: All analysis files can be downloaded as .zip archive
- Added offline HTML analysis reports that can be downloaded and shared with someone without direct access to Drakvuf Sandbox
- Support for "shellexec" injection method and runas elevation
- Improved iptables rules, added conntrack drop after analysis

Known issues:

- Analysis may hang on Windows 7 with pre-installed Powershell 2.0. It's recommended to upgrade Powershell to at least 5.1. See also `the issue #1199 on Github <https://github.com/CERT-Polska/drakvuf-sandbox/issues/1199>`_.

This version was tested using `DRAKVUF v1.1-8107f115 <https://github.com/tklengyel/drakvuf/commit/8107f115d35311d483e314f48c3b172e094ec6e9>`_ and may not work correctly with older versions.
It's recommended to upgrade DRAKVUF to this version or newer before running analyses.

After upgrading Drakvuf engine, it's also recommended to regenerate VMI profiles to include the 64-bit .NET ``clr.dll`` profile. This can be
done by doing the following operations:

- shut down all of the workers and ensure that all of the guest VMs are stopped
- run ``drakrun modify-vm0 begin`` to start VM-0
- after ensuring that VM started correctly, run ``drakrun modify-vm0 commit`` to create a new snapshot and refresh the VMI profiles.

It's recommended to read the :ref:`Managing snapshots` documentation section before running these operations.

Complete changelog can be found here: `v0.21.0 changelog <https://github.com/CERT-Polska/drakvuf-sandbox/releases/tag/v0.21.0>`_.

v0.20.0
-------

This release mostly fixes the bugs found in v0.19.0.

The new addition is an experimental "Extract archive" option for guest-side archive extraction using Expand-Archive or 7-Zip installed on guest VM. It works well, but it's still WIP so it's not yet documented and may change in the future.

This version was tested using `DRAKVUF v1.1-f619440 <https://github.com/tklengyel/drakvuf/tree/f61944014baf7f8c52d7ad97c33c610e3b3ad356>`_.

Complete changelog can be found here: `v0.20.0 changelog <https://github.com/CERT-Polska/drakvuf-sandbox/releases/tag/v0.20.0>`_.

v0.19.0
-------

v0.19.0 is a complete rewrite compared to v0.18.x. That's why it's recommended to start from scratch
and bring up a new instance.

Not everything changed though and you may still try to reuse your guest disk image or parts of your previous configuration.
Here the list of the most crucial changes comparing to v0.18.x:

- There is no built-in Karton integration. The main interface for interacting with sandbox is Web UI/API.
- Analyses are by default stored locally in ``/var/lib/drakrun/analyses``. S3 integration is optional.
- There is no ``drakplayground``. Former ``draksetup`` CLI command is now ``drakrun`` and comes with a rich toolset for configuration and debugging.
- Volume structure has not changed, so if you use e.g. qcow2 backend, you will still find ``vm-0.img`` in ``/var/lib/drakrun/volumes``.
  ``snapshot.sav`` is still there as well.
- ``/etc/drakrun`` changes:

  - ``config.ini`` is now ``config.toml``. Configuration structure changed significantly, so you can't apply previous configuration file directly.
  - XL template is moved from ``scripts/cfg.template`` to ``cfg.template``. There is an additional serial port device that is required for drakshell.
  - VNC password was moved from ``cfg.template`` to ``install.json``. ``install.json`` should keep all variables that
    are applied on ``cfg.template``
  - There is no ``configs`` dir, generated configurations are moved to ``/var/lib/drakrun/configs`` and should not be changed by user.

- Analysis files structure is a bit different:

  - There are no `apicall` and `index` directories. Per-process logs are indexed using ``log_index`` file. It's a binary file so if you want to check its structure, check the ``drakrun.analyzer.postprocessing.indexer`` module.
  - ``dumps.zip`` doesn't contain ``.metadata`` files. More information about dumps can be found in ``metadata.json`` and ``report.json`` files
  - S3 directories are additionally prefixed with the first 4 letters of the UUID ``0/f/2/9/0f29ae1f-322a-496a-a79e-92d3a859053d/<...>`` and we call it "hash pathing", because same thing is done in MWDB S3 integration.
    Some S3 backends map the object name directly to the file-system hierarchy, so this naming highly increases S3 operation performance.
  - Other files should follow the same convention as in previous versions.

- Drakvuf Sandbox Web UI and API changed a lot, but API is documented in ``http://<your web host>/openapi/swagger``
