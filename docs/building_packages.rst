Building installation packages
##############################

In order to build installation packages on your own, you must first `install Docker <https://docs.docker.com/install/linux/docker-ce/debian/>`_ on your machine.

DRAKVUF Sandbox (drakcore, drakrun)
===================================


You may build your packages from source using following commands:

.. code-block:: console

    $ git clone https://github.com/CERT-Polska/drakvuf-sandbox.git
    $ cd drakvuf-sandbox
    $ sudo ./drakcore/package/build.sh
    $ sudo ./drakrun/package/build.sh

Afterwards, you should find your installation packages produced in `out/` directory.

DRAKVUF (drakvuf-bundle)
========================

The build scripts for `drakvuf-bundle` are part of `tklengyel/drakvuf <https://github.com/tklengyel/drakvuf>`_ repository. You may build your package using the following commands:

.. code-block:: console

    $ git clone --recursive https://github.com/tklengyel/drakvuf
    $ cd drakvuf
    $ sudo ./package/build.sh

The resulting package will be produced to ``package/out/`` directory.
