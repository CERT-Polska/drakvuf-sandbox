Contribute to DRAKVUF Sandbox
=============================

Development system
------------------

Very first thing to consider is to setup and configure your local instance of DRAKVUF Sandbox. There are two basic options in that matter:

* Develop on local machine: Install Debian Buster in [VMware Workstation 15 Player](https://www.vmware.com/products/workstation-player/workstation-player-evaluation.html).
* Develop on a remote server: Just get some bare-metal or rent a dedicated server (e.g. [Kimsufi](https://www.kimsufi.com/us/en/servers.xml)) with Debian Buster.

**Caution!** Your host machine must be an Intel processor with VT-x and EPT support, even when using VMware or other nested virtualization.
DRAKVUF will not run on incompatible processors, as it directly relies on particular hardware virtualization extensions.


Install `drakcore` or `drakrun` locally
---------------------------------------

1. Clone the repository:
   ```
   git clone https://github.com/CERT-Polska/drakvuf-sandbox.git
   cd drakvuf-sandbox
   ```
2. Install local `drakcore` and `drakrun`.
   ```
   python3 -m venv venv
   source venv/bin/activate
   pip3 install --editable ./drakcore/
   pip3 install --editable ./drakrun/
   ```
