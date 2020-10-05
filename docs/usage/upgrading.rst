=========
Upgrading
=========

We strive to make the installation and upgrade process as simple as possible,
so in order to use a new version you have to perform just a few steps.

.. warning ::
    Always install correct package versions and perform all upgrade steps.
    Mismatching packages from different releases may lead to unexpected results.

Before upgrading the sandbox, stop the sandbox workers:

.. code-block :: console

    # systemctl stop drakrun@*

.. note ::
    If some analyses are running, the command will block until they've finished.


Install new packages and reboot:

.. code-block :: console

    # apt install ./drakvuf-bundle*.deb
    # apt install ./drakrun*.deb
    # apt install ./drakcore*.deb
    # systemctl reboot


After rebooting, make sure that all of the services are running with a command:

.. code-block :: console

    # drak-healthcheck

