Using drakpdb tool
##################

The `drakpdb` tool allows you to:

* determine PDB name and GUID age given an executable file (e.g. DLL)
* fetch PDB with given name and GUID age
* parse PDB into a profile that could be plugged into DRAKVUF

Usage examples
==============

.. code-block:: console
    root@zen2:~/drakvuf# drakpdb pdb_guid --file ntdll.dll
    {'filename': 'wntdll.pdb', 'GUID': 'dccff2d483fa4dee81dc04552c73bb5e2'}
    root@zen2:~/drakvuf# drakpdb fetch_pdb --pdb_name wntdll.pdb --guid_age dccff2d483fa4dee81dc04552c73bb5e2
    100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 2.12M/2.12M [00:00<00:00, 2.27MiB/s]
    root@zen2:~/drakvuf# drakpdb parse_pdb --pdb_name wntdll.pdb > profile.json
