==================
Regression testing
==================

Introduction
------------

Memory dumping is one of the core functionalities used for automated malware
analysis. Unpacked or decrypted memory is saved for futher analysis with YARA
rules or configuration extraction. Thus, it's important to ensure that DRAKVUF
development does cause any regressions that would break existing sample analysis.

Preparing a test set
--------------------

Regression test set is a list of JSON objects that represent a number of sample
submissions and the expected malware family name that should be detected.

Dump analysis is performed by providing a directory with
`malduck <https://malduck.readthedocs.io/en/latest/>`_ extractor modules.
`Here <https://malduck.readthedocs.io/en/latest/extractor.html>`_, you can learn
more about them.

  * sha256 - SHA256 hash of the sample file
  * extension - file extension, supported by the sanbox, e.g. "exe" or "dll"
  * ripped - malware family name
  * path - (optional) path to the malware sample

Example:

.. code-block:: json

    [
        {
            "sha256": "35e756ef1b3d542deaf59f093bc4abe5282a1294f7144b32b61f4f60c147cabb",
            "extension": "dll",
            "ripped": "emotet"
        },
        {
            "sha256": "4239335443cbf3d45db485d33c13346c67d5ac717a57856315a166c190dde075",
            "extension": "exe",
            "ripped": "raccoon",
            "path": "samples/4239335443cbf3d45db485d33c13346c67d5ac717a57856315a166c190dde075"
        }
    ]

Test submitter supports two methods for obtaining the malware sample. 

1. Manual - if the test case has a ``path`` key deinfed, malware sample will be read
   from this location (relative and absolute paths are allowed).
2. Automated - otherwise, sample will be downloaded from the mwdb.cert.pl service.
   Make sure to run the submitter with ``MWDB_API_KEY`` environment variable if you
   intend to use this method

Running the receiver daemon
---------------------------

First, configure the extractor module path in ``/etc/drakrun/config.ini``

.. code-block:: ini

    [draktestd]
    ; path to the extraction modules for
    ; https://github.com/CERT-Polska/malduck
    modules=/opt/extractor-modules/
    
Next, uncomment ``sample_testing`` line and enable it

.. code-block:: ini

    [drakrun]
    ; (advanced) Enable testing codepaths. Test sample artifacts will not be uploaded
    ; to persistent storage. Their lifetime will be bound to karton tasks produced by drakrun
    sample_testing=1

Then, execute

.. code-block:: console

    $ draktestd


This will spawn a new karton service listening for test analysis results and printing
the results.


Executing a test set
--------------------

To submit a test set, execute:

.. code-block:: console

    $ draktest test_set.json

The command will submit samples to the sandbox and wait until all the testing is finished.
