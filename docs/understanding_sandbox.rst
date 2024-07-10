=========================
Understanding the sandbox
=========================

Tech stack
----------
DRAKVUF Sandbox is built on top of a few layers of software and hardware technologies:

* Intel VT-x and EPT - extensions to x64 architecture that allow to run virtual machines natively on a CPU
* Xen - hypervisor, spawns virtual machines and exposes interfaces for interaction and introspection
* LibVMI - abstracts away introspection interfaces, provides utilities for reading/writing VM memory, parsing VMs' kernel and handling notifications about certain events happening in a VM
* DRAKVUF - stealthily hooks various parts of a guest VM and logs interesting events
* DRAKVUF Sandbox - provides user friendly interface and high level analyses

Daemons
-------

* ``drakrun 1..n`` - fetches incoming samples for analysis, runs VMs, and sends back results of analysis; each daemon handles one concurrent VM
* ``drak-web`` - web interface that allows user to interact with the sandbox with either REST API or GUI
* ``karton-system`` (vel ``drak-system``) - internal task management system, using for dispatching jobs between workers.

Lifecycle of a analysis
-----------------------

1. User submits new analysis with a browser or programatically using *karton* API.
2. ``karton-system`` dispatches the job to one of the ``drakrun`` instances.
3. ``drakrun`` runs the analysis:

     - preconfigured virtual machine image is restored
     - sample is uploaded to the VM using DRAKVUF's ``injector``
     - sample is executed 
     - after a chosen timeout, virtual machine is destroyed

4. Processed results (dumps, logs, pcaps) are sent back to ``karton-system`` as a *karton* task.
