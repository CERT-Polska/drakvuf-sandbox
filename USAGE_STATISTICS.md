Usage statistics
================

Installation report
-------------------

By default, DRAKVUF Sandbox is sending anonymous usage statistics:

* The random unique instance ID
* Installation ISO SHA256 SUM
* Kernel version, PDB name and GUID

the main purposes for collecting such information are:

* determining the popularity of DRAKVUF Sandbox
* improving compatibility with most popular Windows builds

If for some reason you don't want to send any usage reports,
you could use `--no-report` switch with `draksetup postinstall` command.

You can also execute this command in order to permanently disable reporting:

```
touch /etc/drakrun/no_usage_reports
```


External interactions
---------------------

Please be aware that DRAKVUF Sandbox is also connecting to Microsoft Symbol
Server in order to download kernel's PDB. Moreover, your Windows guest may
also send some default telemetry reports unless configured accordingly.

