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

Project structure
-----------------
DRAKVUF Sandbox is divided into two packages:

* drakcore - system core, provides a web interface, an internal task queue and object storage
* drakrun - sandbox worker, wrapper for DRAKVUF, responsible for managing VMs, running analyses and sending results for further postprocessing.

.. note ::
   `DRAKVUF engine <https://github.com/tklengyel/drakvuf>`_ is a separate project authored by Tamas K Lengyel.
   
DRAKVUF Sandbox is built around *karton* -- microservice framework created at CERT Poland
as a specialized tool for building flexible malware analysis pipelines. Its main goal
is routing tasks between multiple services.

As of now, documentation for *karton* isn't publically available, however this will change
in the future.
   
Daemons
-------

* drakcore package

   * ``drak-web`` - web interface that allows user to interact with the sandbox with either REST API or GUI
   * ``drak-system`` - internal task management system, using for dispatching jobs between workers
   * ``drak-minio`` - builtin object storage in which analysis results are stored
   * ``drak-postprocess`` - responsible for processing raw analysis logs into more usable form

* drakrun package

   * ``drakrun 1..n`` - fetches incoming samples for analysis, runs VMs, and sends back results of analysis; each daemon handles one concurrent VM
   
Lifecycle of a analysis
-----------------------

1. User submits new analysis with a browser or programatically using *karton* API.
2. ``drak-system`` dispatches the job to one of the ``drakrun`` instances.
3. ``drakrun`` runs the analysis:

     - preconfigured virtual machine image is restored
     - sample is uploaded to the VM using DRAKVUF's ``injector``
     - sample is executed 
     - after a chosen timeout, virtual machine is destroyed

4. Raw results (dumps, logs, pcaps) are sent back to ``drak-system`` as a *karton* task.
5. ``drak-system`` dispatches a task to ``drak-postprocess`` which extracts interesting data for the user


