======================
Advanced configuration
======================

Supported configuration fields
==============================

DRAKVUF Sandbox configuration is defined in ``/etc/drakrun/config.toml`` file. Here is the specification:

[redis] section
~~~~~~~~~~~~~~~

This section defines the Redis configuration used by RQ queues.

.. list-table::
   :header-rows: 1

   * - Field
     - Default value
     - Description
   * - host
     - "localhost"
     - Hostname of Redis instance
   * - port
     - 6379
     - Port of Redis instance
   * - username
     - None
     - Username when Redis authentication is enabled and required (optional)
   * - password
     - None
     - Password when Redis authentication is enabled and required (optional)

[network] section
~~~~~~~~~~~~~~~~~

This section defines the network configuration used by guest VMs.

.. list-table::
   :header-rows: 1

   * - Field
     - Default value
     - Description
   * - dns_server
     - "use-gateway-address"
     - DNS server used by VM. Can be IPv4 or "use-gateway-address" if you want to forward your DNS traffic
       to the dnsmasq and use your system resolver configuration (default)
   * - out_interface
     - "default"
     - Name of the output interface that will be bridged with the VM. Using a non-default interface may need
       an additional configuration because different default gateway will be required for routing the VM traffic.
       See also "Customizing network configuration".
   * - net_enable
     - false
     - Enables Internet access for the VM. You can switch it to true after initial installation of VM-0.

[s3] section
~~~~~~~~~~~~

This section defines the S3 configuration used for storing analyses in S3 bucket.

.. list-table::
   :header-rows: 1

   * - Field
     - Default value
     - Description
   * - enabled
     - true
     - If section is defined, S3 is automatically enabled. If you want to temporarily disable it and use
       local file-system for storage, set it to false.
   * - address
     - <no default>
     - Address of S3 instance
   * - access_key
     - <no default>
     - Access key for S3 authentication
   * - secret_key
     - <no default>
     - Secret key for S3 authentication
   * - bucket
     - "drakrun"
     - Name of the bucket that is used for storing analyses.
   * - iam_auth
     - false
     - Use IAM for authentication
   * - remove_local_after_upload
     - true
     - Analysis logs are still written in ``/var/lib/drakrun/analyses`` during collection. By default, they're
       removed after upload. If you don't want to remove them (e.g. for debug purposes), set this flag to false.

[drakrun] section
~~~~~~~~~~~~~~~~~

This section defines various analysis parameters.

.. list-table::
   :header-rows: 1

   * - Field
     - Default value
     - Description
   * - plugins
     - ["apimon", "clipboardmon", "exmon", "filetracer", "memdump", "procmon", "regmon", "socketmon", "tlsmon"]
     - Default plugins used when no plugins were provided via CLI/API. We have listed there plugins that
       we're supporting out of the box. Additional plugins may need extra configuration, see also
       "Adding extra directories and flags to Drakvuf command line"
   * - default_timeout
     - 300
     - Default sample execution timeout in seconds, when no timeout was provided via CLI/API.
   * - job_timeout_leeway
     - 600
     - Additional timeout (in seconds) that is added to the execution timeout. It defines how long RQ will wait for
       non-execution parts of analysis like VM boot, launching post-restore scripts, log post-processing and S3 upload.
       If your setup is not fast enough and your analyses fail because of that, you should increase this value.
   * - apimon_hooks_path
     - None
     - Alternative hooks configuration for "apimon" plugin. See also "Customizing apimon hooks"
   * - syscall_hooks_path
     - None
     - Alternative syscall filter configuration for "syscalls" plugin. See also "Customizing syscall filter"
   * - extra_drakvuf_args
     - None
     - Additional Drakvuf arguments. See also "Adding extra directories and flags to Drakvuf command line"
   * - extra_output_subdirs
     - None
     - Additional subdirectories created in analysis output directory. See also "Adding extra directories and flags to Drakvuf command line"
   * - no_post_restore
     - false
     - Don't run post-restore script when analysis is started.
   * - no_screenshoter
     - false
     - Don't make VNC screenshots during analysis.
   * - result_ttl
     - -1
     - Defines how long in seconds the analysis job should be kept in Redis and listed in recent analysis list. By default we don't use
       any timeout and we keep 100 analyses. All analyses stored locally or in S3 are always available for preview via UUID, this setting changes
       only the analysis appearance in the recent list.
   * - gzip_syscalls
     - false
     - If enabled, syscall.log is gzipped and not available for direct preview.

[capa] section
~~~~~~~~~~~~~~

This section defines parameters for Capa postprocessing (TTPs).

.. list-table::
   :header-rows: 1

   * - Field
     - Default value
     - Description
   * - rules_directory
     - <Python package dir>/data/capa-rules
     - Alternative directory with Capa rules
   * - analyze_drakmon_log
     - true
     - Extract TTPs from Drakvuf logs (default)
   * - analyze_memdumps
     - false
     - Extract TTPs from memdumps
   * - analyze_only_malware_pids
     - false
     - Extract TTPs only from sample process and its children.
   * - worker_pool_processes
     - 4
     - How many processes should be used for processing parallelization.

[memdump] section
~~~~~~~~~~~~~~~~~


.. list-table::
   :header-rows: 1

   * - Field
     - Default value
     - Description
   * - max_total_dumps_size
     - 524288000 (500 MB)
     - Maximum total size in bytes of collected, uncompressed dumps. When collected dumps exceed this value,
       DRAKVUF Sandbox will remove some dumps starting from the most commonly dumped memory regions and dumps
       made near the end of the analysis.
   * - min_single_dump_size
     - 512
     - Minimal accepted size of a single memory dump. Dumps that are smaller in size than that are removed.
   * - min_single_dump_size
     - 33554432 (32 MB)
     - Maximal accepted size of a single memory dump. Dumps that are bigger in size than that are removed.
   * - filter_out_system_pid
     - true
     - By default, dumps made for System process (PID 4) are filtered out and removed. If you want to keep them,
       set this flag to false

[preset.<preset_name>] sections
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Preset configuration. Accepts mostly the same fields as ``[drakrun]`` section. Read more about it in "Configuration presets" section.

Advanced DRAKVUF engine configuration
=====================================

Customizing apimon hooks
------------------------

You can customize the list of hooked WinAPI by apimon plugin. By default, the list is taken from these paths:

* Path configured in ``[drakrun].apimon_hooks_path``
* If doesn't exist, then ``/etc/drakrun/hooks.txt``
* If doesn't exist, then ``<package dir>/data/hooks.txt`` (embedded list)

The format of ``hooks.txt`` is defined as follows:

.. code-block:: csv

    <dll name>,<function name>,<flags>,<argtype1>,...,<argtypeN>

e.g.

.. code-block:: csv

    jscript.dll,COleScript_ParseScriptText,log,pvoid,pwchar,pvoid,pvoid,pvoid,pvoid,pvoid,pvoid,pvoid,pvoid
    jscript.dll,JsEval,log,pvoid,pvoid,pvoid,index,dword
    jscript9.dll,JsParseScript,log,wchar_t,pvoid,wchar_t,pvoid
    jscript9.dll,JsRunScript,log,wchar_t,pvoid,wchar_t,pvoid
    mshtml.dll,CDocument_write,log+stack,pvoid,safearray

Flags value can be ``log``, ``stack`` or ``log+stack``. ``log`` means that API call to the function will be recorded by apimon.
``stack`` means that API call will be a trigger for memdump plugin to dump the caller's memory region.


Customizing syscall filter
--------------------------

You can also customize the list of hooked syscalls by syscall plugin. By default, the list is taken from these paths:

* Path configured in ``[drakrun].syscall_hooks_path``
* If doesn't exist, then ``/etc/drakrun/syscalls.txt``
* If doesn't exist, then ``<package dir>/data/syscalls.txt`` (embedded list)

``syscalls.txt`` is just a simple newline-separated list of Nt* function names. Syscall number and argument types are deduced automatically by the DRAKVUF engine.

Adding extra directories and flags to DRAKVUF command line
----------------------------------------------------------

Some plugins need additional configuration provided via arguments to DRAKVUF command line. If you want to use plugin that we don't support directly
or you want to customize the DRAKVUF behavior, you can pass additional arguments and create extra output subdirs using ``[drakrun].extra_drakvuf_args`` and
``[drakrun].extra_output_subdirs`` values.

``[drakrun].extra_drakvuf_args`` accepts key/value pairs, following the `TOML table syntax <https://toml.io/en/v1.0.0#inline-table>`_
Key defines the argument and value defines the value for this argument. When value is ``true``, argument is considered a flag and is added without a value.
If you need to, you can also override default flags applied by DRAKVUF Sandbox as well. E.g. using ``false`` value, we can remove the default flag applied by DRAKVUF Sandbox.

The following example creates ``extracted_files`` subdirectory to be used by fileextractor plugin and adds ``--disable-sysret`` flag for syscalls plugin.

.. code-block:: toml

   [drakrun]
   # ...
   extra_drakvuf_args = {"--disable-sysret" = true, "-D" = "extracted_files"}
   extra_output_subdirs = ["./extracted_files"]

Changing post-restore script
============================

DRAKVUF Sandbox launches by default a simple Powershell script after starting a VM for analysis. The script does two things:

- runs ``ipconfig /release`` and ``ipconfig /renew`` to fetch machine IP and DNS server from DHCP (dnsmasq) when ``net_enable`` is true
- runs elevated shell with ``Set-Date -Date $DRAKVUF_DATE`` command to synchronize the clock.

If you want to customize it, you can create ``/etc/drakrun/vm-post-restore.ps1`` to run your own script.

Customizing network configuration
=================================

Every time the VM is started, DRAKVUF Sandbox creates ``drakN`` bridge, starts ``dnsmasq`` and applies iptables rules to setup the network.
In non-trivial configurations you may want to run your own commands.

You can provide your own scripts that are executed each time the network is created:

- ``/etc/drakrun/vmnet-pre.sh`` executed before the network is created
- ``/etc/drakrun/vmnet-post.sh`` executed after the network is created

e.g. the following ``vmnet-post.sh`` script can be used for setting up an alternative routing table to route VM traffic
through different interface than the default one (in our case it was "enp2s0")

.. code-block:: bash

   #!/bin/bash

    set -e

    if [ $NET_ENABLE = "False" ]
    then
       echo "Net disabled - nothing to setup"
       exit 0
    fi
    if [ $OUT_INTERFACE != "enp2s0" ]
    then
       echo "Out interface is $OUT_INTERFACE - nothing to setup"
       exit 0
    fi

    echo [*] Setting alternative route table...
    echo [*] Network address: ${NETWORK_ADDRESS}
    echo [*] Bridge name: ${BRIDGE_NAME}

    ip route add ${NETWORK_ADDRESS} dev ${BRIDGE_NAME} table 1000
    ( ip rule | grep "iif ${BRIDGE_NAME} lookup 1000" ) || ip rule add iif ${BRIDGE_NAME} lookup 1000

    echo "=== Routing table: ==="
    ip route list table 1000

    echo "=== Rules: ==="
    ip rule

Another common use-case is limiting the bandwidth for the VM: https://wiki.gentoo.org/wiki/Traffic_shaping

.. code-block:: bash
    #!/bin/sh

    # Based on https://wiki.gentoo.org/wiki/Traffic_shaping

    modprobe ifb

    ## Paths and definitions
    ext=${BRIDGE_NAME}  # Change for your device!
    ext_ingress=ifb${BRIDGE_NAME} # Use a unique ifb per rate limiter!
    ext_up=1Mbit        # Max theoretical: for this example, up is 1024kbit
    ext_down=1Mbit      # Max theoretical: for this example, down is 1024kbit
    q=1514              # HTB Quantum = 1500bytes IP + 14 bytes ethernet.
                        # Higher bandwidths may require a higher htb quantum. MEASURE.
                        # Some ADSL devices might require a stab setting.

    # Clear old queuing disciplines (qdisc) on the interfaces
    tc qdisc del dev $ext root
    tc qdisc del dev $ext ingress
    tc qdisc del dev $ext_ingress root
    tc qdisc del dev $ext_ingress ingress

    #########
    # INGRESS
    #########

    # Create ingress on external interface
    tc qdisc add dev $ext handle ffff: ingress

    ifconfig $ext_ingress up # if the interace is not up bad things happen

    # Forward all ingress traffic to the IFB device
    tc filter add dev $ext parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev $ext_ingress

    # Create an EGRESS filter on the IFB device
    tc qdisc add dev $ext_ingress root handle 1: htb default 11

    # Add root class HTB with rate limiting

    tc class add dev $ext_ingress parent 1: classid 1:1 htb rate $ext_down
    tc class add dev $ext_ingress parent 1:1 classid 1:11 htb rate $ext_down prio 0 quantum $q

    #########
    # EGRESS
    #########

    # Add FQ_CODEL to EGRESS on external interface
    tc qdisc add dev $ext root handle 1: htb default 11

    # Add root class HTB with rate limiting
    tc class add dev $ext parent 1: classid 1:1 htb rate $ext_up
    tc class add dev $ext parent 1:1 classid 1:11 htb rate $ext_up prio 0 quantum $q

Configuration presets
=====================

DRAKVUF Sandbox implements configuration mechanism called "preset". We can define alternative ``[drakrun]`` configurations
depending on which "preset" was chosen in analysis options. Presets are not yet exposed in the Web UI, but can be used
via API and CLI.

To create a new preset, simply add proper ``[preset.<preset name>]`` section in the ``/etc/drakrun/config.toml`:

.. code-block::

   [drakrun]
   default_timeout = 300
   plugins = ["apimon", "clipboardmon", "exmon", "filetracer", "memdump", "procmon", "regmon", "socketmon", "tlsmon"]

   [preset.windows-api-plus-prod-syscalls]
   plugins = ["procmon", "apimon", "socketmon", "syscalls"]
   extra_drakvuf_args = {"--disable-sysret" = true}
   apimon_hooks_path = "/opt/hooks/windows-api-plus-prod-hooks-nont.lst"
   syscall_hooks_path = "/opt/hooks/windows-api-syscalls.lst"

Then you can use ``preset`` parameter in ``POST /api/upload`` API or ``--preset`` in CLI to use the alternative
configuration preset. Values defined in preset override the values defined in ``[drakrun]`` section.

The only field you can't override is ``result_ttl``.
