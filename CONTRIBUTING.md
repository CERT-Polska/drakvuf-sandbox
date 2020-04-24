Contribute to DRAKVUF Sandbox
=============================

## Setup development environment

### Prerequisites

Very first thing to consider is to setup and configure your local instance of DRAKVUF Sandbox. There are two basic options in that matter:

* Develop on local machine: Install Debian Buster in [VMware Workstation 15 Player](https://www.vmware.com/products/workstation-player/workstation-player-evaluation.html).
* Develop on a remote server: Just get some bare-metal or rent a dedicated server (e.g. [Kimsufi](https://www.kimsufi.com/us/en/servers.xml)) with Debian Buster.

**Caution!** Your host machine must be an Intel processor with VT-x and EPT support, even when using VMware or other nested virtualization. You can check it by executing the following command on your native system (i.e. host system and without hypervisor loaded):

```
# should return non-empty output and exit code 0
lscpu | grep -i flags | grep -w ept
```

DRAKVUF will not run on incompatible processors, as it directly relies on particular hardware virtualization extensions.


### Clone the repository

In order to obtain the source code of DRAKVUF Sandbox, you need to execute the following commands:

```
git clone https://github.com/CERT-Polska/drakvuf-sandbox.git
cd drakvuf-sandbox
```

### Build Debian packages

The DRAKVUF Sandbox distribution packages are built using Docker, in order to make them more reproducible. In order to build the packages by yourself, perform the following steps:

1. Obtain and install [Docker](https://docs.docker.com/engine/install/debian/).
2. Execute:
   ```
   sh drakcore/package/build.sh
   sh drakrun/package/build.sh
   ```
3. The Debian packages will be produced to the `out/` directory. You can install them similarly as you would install the released packages. See ["Basic installation" section of README.md](https://github.com/CERT-Polska/drakvuf-sandbox/blob/icedevml-patch-1/README.md#basic-installation).


### Install editable Python packages

Now you can re-install Python packages from sources, using:

```
/opt/venvs/drakcore/bin/pip3 install --editable ./drakcore/
/opt/venvs/drakrun/bin/pip3 install --editable ./drakrun/
```

your changes to the DRAKVUF Sandbox services will be immediately visible after you restart them.

### Test local changes

1. Open `drakcore/drakcore/app.py`
2. Add these lines before `def main()`:
   ```python
   @app.route("/hello-world")
   def hello_world():
       return 'hello'
   ```
3. Save the file and execute `systemctl restart drak-web`
4. Navigate to `http://localhost:6300/hello-world`, your new subpage should appear.
