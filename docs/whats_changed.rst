===============================
What's changed, how to upgrade?
===============================

v0.19.0
-------

v0.19.0 is a complete rewrite compared to v0.18.x. That's why it's recommended to start from scratch
and bring up a new instance. o

Not everything changed though and you may still try to reuse your guest disk image or parts of your previous configuration.
Here the list of the most crucial changes comparing to v0.18.x:

- There is no built-in Karton integration. The main interface for interacting with sandbox is Web UI/API.
- Analyses are by default stored locally in ``/var/lib/drakrun/analyses``. S3 integration is optional.
- Volume structure has not changed, so if you use e.g. qcow2 backend, you will still find ``vm-0.img`` in ``/var/lib/drakrun/volumes``.
  ``snapshot.sav`` is still there as well.
- ``/etc/drakrun`` changes:
  - ``config.ini`` is now ``config.toml``. Configuration structure changed significantly, so you can't apply previous configuration file directly.
  - XL template is moved from ``scripts/cfg.template`` to ``cfg.template``. There is additional serial port device
    that is required for drakshell.
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
