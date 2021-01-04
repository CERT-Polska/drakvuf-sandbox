===================
DRAKVUF Sandbox FAQ
===================

Can I run DRAKVUF Sandbox in the cloud?
---------------------------------------

We've done some research regarding the deployment of the sandbox in the cloud.
Unfortunately, due to the nature of the project and extensive use of low level CPU features,
none of the popular "instance" services were able to run DRAKVUF.
If you're interested to learn more about underlying problems see `relevant issues on GitHub <https://github.com/CERT-Polska/drakvuf-sandbox/issues?q=label%3Anested>`_.

However, this doesn't mean that cloud deployment is impossible. You can still leverage modern
deployment techniques and IaC (infrastracture as code) using bare metal servers.

Tested service providers:

* `Equinix Metal <https://metal.equinix.com/>`_
* `Scaleway Bare Metal <https://www.scaleway.com/en/bare-metal-servers/>`_

Unfortunately, AWS EC2 Metal seems to be broken at the moment (see `this issue <https://github.com/CERT-Polska/drakvuf-sandbox/issues/222>`_).
If you've managed to run DRAKVUF Sandbox on a previously untested cloud service, send us a PR to add it to this list.

.. _check-cpu:

How can I verify if my CPU is supported?
----------------------------------------

If you're running fairly recent Intel CPU, it's probably going to have all of the required features.

0. Make sure VT-x extensions are enabled in BIOS.
1. Check virtualization extensions support.

   .. code-block :: console

    $ lscpu | grep vmx

2. Check EPT support.

   .. code-block :: console

    $ lscpu | grep ept

If both flags are present, you're good to go.

I have an AMD CPU which supports NPT. Can I run DRAKVUF Sandbox?
----------------------------------------------------------------

DRAKVUF is tightly coupled with `alpt2m <https://xenproject.org/2016/04/13/stealthy-monitoring-with-xen-altp2m/>`_ feature, implemented
only for Intel CPUs. Thus it's not possible to run it on a AMD CPU.


I have some other question
--------------------------

Feel free to `submit an issue <https://github.com/CERT-Polska/drakvuf-sandbox/issues/new/choose>`_, write us an email or contact in any other way.
