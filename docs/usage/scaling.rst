Scaling
=======

Introduction
------------

After performing installation, by default, your sandbox instance will be capable of processing one sample at a time. The service that performs the actual analysis is called `drakrun@<instance_number>`. You can check the state of a particular instance by executing:

.. code-block:: console

  systemctl status drakrun@1

You can change the number of parallel workers by executing:

.. code-block:: console

  draksetup scale <num_instances>

Scaling up
----------

Assuming you have a single instance but you want to be able to process 10 samples in parallel, you should execute:

.. code-block:: console

  draksetup scale 10

The setup script will configure and start additional instances named from ``drakrun@2`` to ``drakrun@10``.

Scaling down
------------

Analogously, you can scale down by repeating the same command with the smaller number of instances, e.g.:

.. code-block:: console

  draksetup scale 7


Assuming you had 10 instances previously, it will cause ``drakrun@8`` to ``drakrun@10`` to be disabled and shut down. If the analysis is pending on these instances, the command will gracefully wait until it's finished.
