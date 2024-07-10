==================
Karton integration
==================

Connecting to existing Karton system
------------------------------------

In a simple installation, DRAKVUF Sandbox relies on services provided by
the deb package and a local Redis instance.
It is however possible to integrate it with a larger, karton-based pipeline.
Doing this requires only a few steps:

1. Stop all ``drak-*`` services, if they're running.
2. Copy Karton configuration to appropriate sections in ``/etc/drakrun/config.ini``.
3. Restart all stopped services.

.. note ::
    Karton GC removes resources when they're not referenced by any task. This is
    why analysis artifacts are stored in ``drakrun`` bucket instead of the one used by karton.
    Karton services that depend on the sandbox also have to be granted access to this bucket.

If you want to configure Drakvuf Sandbox to work with existing Karton configuration from the start,
you can omit configuring ``drak-system`` by running ``draksetup init`` with these flags:

.. code-block:: console

    $ draksetup init --only web --only drakrun

Building integrations
---------------------

To create an integration, some familiarity with karton library is required.
`Here <https://karton-core.readthedocs.io/en/latest/task_headers_payloads.html>`_ you can learn more about basic concepts such as tasks, headers or payloads.

Submitting samples from karton
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In default configuration, `drakrun` services listen for tasks that contain headers:

  * type: sample
  * stage: recognized
  * platform: win32/win64

You can find an example `here <https://github.com/CERT-Polska/drakvuf-sandbox/blob/master/examples/push_sample.py>`_.

Analysis task structure
^^^^^^^^^^^^^^^^^^^^^^^

In default configuration, analysis tasks are guaranteed to have the following structure:

Headers:
  * type: analysis
  * kind: drakrun

Payload:
  * ``sample`` - analyzed sample (Resource)
  * ``[plugin_name].log`` - DRAKVUF log emitted by given plugin (Resource)

    * present when the plugin was enabled and generated some output

  * ``dumps.zip`` - ZIP file containing extracted memory dumps (Resource)
  * ``dumps_metadata`` - List of dicts with keys: (list)

    * ``base_address`` - virtual base address of dump (in hexadecimal) (str)
    * ``filename`` - path to file inside the dump ZIP file, relative to root


  * ``dumps.pcap`` - Recorded network traffic (Resource)
  * ``wireshark_key_file.txt`` -  (Resource)

    * present only when `tlsmon` was enabled and keys were successfully extracted

  * ``metadata`` - basic facts about analysis (dict);

    * ``sample_sha256`` - hexencoded SHA256 sum of analyzed sample (str)
    * ``magic_output`` - libmagic output for the sample (str)
    * ``time_started`` - UNIX timestamp of analysis start (int)
    * ``time_finished`` - UNIX timestamp of analysis end (int)
    * ``snapshot_version`` - UNIX timestamp of VM snapshot (int)

`Here <https://github.com/CERT-Polska/drakvuf-sandbox/blob/master/examples/consumer.py>`_ 
you can find an example analysis consumer.
