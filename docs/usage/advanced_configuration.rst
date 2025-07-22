======================
Advanced configuration
======================

Supported configuration fields
==============================

DRAKVUF Sandbox configuration is defined in ``/etc/drakrun/config.toml`` file. Here is the specification:

**[redis] section**

This section defines the Redis configuration used by RQ queues.

.. list-table:: Title
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

**[network] section**

This section defines the network configuration used by guest VMs.

.. list-table:: Title
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

**[s3] section**

**[drakrun] section**

This section defines various analysis parameters.

.. list-table:: Title
   :header-rows: 1

   * - Field
     - Default value
     - Description
   * - plugins
     - ["apimon","clipboardmon","exmon","filetracer","memdump","procmon","regmon","socketmon","tlsmon"]
     - Default plugins used when no plugins were provided via CLI/API. We have listed there plugins that we're supporting
       out of the box. Additional plugins may need extra configuration, see also "Adding extra directories and flags to Drakvuf command line"
   * - default_timeout
     - 300
     - Default sample execution timeout in seconds, when no timeout was provided via CLI/API.
   * - job_timeout_leeway
     - 600
     - Additional timeout (in seconds) that is added to the execution timeout. It defines how long RQ will wait for non-execution parts of analysis
       like VM boot, launching post-restore scripts, log post-processing and S3 upload. If your setup is not fast enough and your analyses fail
       because of that, you should increase this value.
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
     - False
     - Don't run post-restore script when analysis is started.
   * - no_screenshoter
     - False
     - Don't make VNC screenshots during analysis.
   * - result_ttl
     - -1
     - Defines how long in seconds the analysis job should be kept in Redis and listed in recent analysis list. By default we don't use
       any timeout and we keep 100 analyses. All analyses stored locally or in S3 are always available for preview via UUID, this setting changes
       only the analysis appearance in the recent list.
   * - gzip_syscalls
     - False
     - If enabled, syscall.log is gzipped and not available for direct preview.

**[capa] section**

**[memdump] section**

**[preset.<preset_name>] sections**

Advanced Drakvuf engine configuration
=====================================

Customizing apimon hooks
------------------------

Customizing syscall filter
--------------------------

Adding extra directories and flags to Drakvuf command line
----------------------------------------------------------

PDB cache for VMI profile generation
------------------------------------

Changing post-restore script
============================

Customizing network configuration
=================================

Configuration presets
=====================
