===================
Sandbox development
===================

DRAKVUF Sandbox is not a typical monolithic application. It is designed to be
deployed over multiple servers either standalone or as a part of a larger karton system.
Multiple components and daemons may be confusing at the beginning.

This is a quick tutorial that should help you when starting to develop the sandbox.

DRAKVUF Sandbox is based on `karton framework <https://karton-core.readthedocs.io/>`_.
It is recommended to become familiar with its concepts before approaching the sandbox code.

.. graphviz::
    :name: sphinx.ext.graphviz
    :caption: High-level view of component interactions
    :alt: How DRAKVUF Sandbox components interact with each other
    :align: center

     digraph "DRAKVUF Sandbox components" {
        rankdir=LR;
        node [fontname="Sans", fontsize="12"];


        user [label="User", shape="circle"];
        webui [label="web UI", shape="box"];
        api [label="API server", shape="box"];
        drakrun [label="drakrun", shape="box"];
        postprocess [label="postprocess", shape="box"];

        user -> webui;
        webui -> api;
        api -> drakrun;
        drakrun -> postprocess;
     }


Web UI (drakcore)
=======================

Serves as an GUI for the user for sample submission and browsing the results.
Built with React and `Hyper bootstrap theme <https://themes.getbootstrap.com/product/hyper-responsive-admin-dashboard-template/>`_.

Code location: `drakcore/drakcore/frontend <https://github.com/CERT-Polska/drakvuf-sandbox/tree/master/drakcore/drakcore/frontend>`_

Development
***********

The prerequisite is to setup a working DRAKVUF Sandbox instance (MinIO, Redis, drakrun and API).
Workflow is going to be similar to developing other React-based apps with a backend API.
Don't forget to run Prettier over the changes. Otherwise CI will reject your code.

.. code-block:: console

    $ cd drakcore/drakcore/frontend
    $ # install dependencies (execute only the first time)
    $ npm install
    $ # point the application at a running instance of API server
    $ export REACT_APP_API_SERVER=http://[API location]:6300/
    $ # start serving the frontend with live reloading
    $ npm start

REST API (drakcore)
===================

Main entrypoint into the sandbox. The intended users are web UI and programmatic integrations with
the sandbox.

Code location: `drakcore/drakcore/app.py <https://github.com/CERT-Polska/drakvuf-sandbox/tree/master/drakcore/drakcore/app.py>`_

Development
***********

REST API is a simple Flask-based Python application.
To work correctly it requires a configuration file (stored in ``/etc/drakcore/config.ini`` on a configured sandbox instance) to reach to Karton 
and drakrun workers.
If you want to run the API server on a different machine than it is originally configured you may have to tweak it a little.

.. code-block:: console

    $ # Create python virtualenv
    $ python -m venv venv
    $ source env/bin/activate
    $ cd drakcore
    $ # Copy the configuration file to the same directory as config.dist.ini
    $ cp /some/config.ini drakcore/config.ini
    $ # Install drakcore dependencies
    $ pip install -r requirements.txt
    $ # Install drakcore in editable mode
    $ pip install -e .
    $ export FLASK_APP=drakcore/app.py
    $ export FLASK_ENV=development
    $ flask run


drakrun (drakrun)
=================

This is the main component that manages the analysis process and the only one that has the requirement
of being deployed on a machine (either virtual or physical) running Xen.

Code location: `drakrun/drakrun <https://github.com/CERT-Polska/drakvuf-sandbox/blob/master/drakrun/drakrun>`_

Development
***********

This is the hardest part to develop as it has to be on a running on a separate machine. 
First, setup the basic environment in the repository:

.. code-block:: console

    $ # Make sure that installed drakrun instance is not running
    $ systemctl stop drakrun@1
    $ # Create Python virtualenv
    $ python -m venv venv
    $ source env/bin/activate
    $ cd drakrun
    $ # Install drakrun dependencies
    $ pip install -r requirements.txt
    $ # Install drakrun in editable mode
    $ pip install -e .
    $ # Start drakrun
    $ python drakrun/main.py 1

drakrun should start listening for new task from the rest of the system. After making some changes
you have to restart the process.

To develop drakrun from your main development machine you can either:

 - mount the repository directory over SSHFS
 - use an IDE integration to edit remote files
 - (advanced) add the drakrun repository on a worker machine as another Git remote and push the changes


postprocessing (drakcore)
=========================

Hypervisor time is precious. This is why it's important to perform as little work as possible in
drakrun process. Analysis postprocessing extracts interesting data from DRAKVUF output and converts
it into a form that is easier to consume by the frontend.

Development
***********

On a drakrun machine:

.. code-block:: console

    $ # Make sure that the installed drak-postprocess instance is not running
    $ systemctl stop drak-postprocess@1


On a development machine:

.. code-block:: console

    $ # Create python virtualenv
    $ python -m venv venv
    $ source env/bin/activate
    $ cd drakcore
    $ # Copy the configuration file to the same directory as config.dist.ini
    $ cp /some/config.ini drakcore/config.ini
    $ # Install drakcore dependencies
    $ pip install -r requirements.txt
    $ # Install drakcore in editable mode
    $ pip install -e .
    $ # Start the postprocess worker
    $ python process.py

Code location (entrypoint): `drakcore/drakcore/process.py <https://github.com/CERT-Polska/drakvuf-sandbox/blob/master/drakcore/drakcore/process.py>`_

Code location (steps): `drakcore/drakcore/postprocess <https://github.com/CERT-Polska/drakvuf-sandbox/tree/master/drakcore/drakcore/postprocess>`_
