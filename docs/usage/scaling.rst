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

Postprocess
-----------

Analysis postprocessing doesn't need hypervisor access, so it can be done in separate servers, assuming they have same configuration and connect to same minio & redis instances. This is highly recommended if you can afford such setup, as this frees resources on servers running hypervisor.

By default only 1 instance of postprocess worker is started and when running multiple instances of drakrun - needs to be scaled up. As a rule of thumb you can assume safe ratio of postprocess to drakrun workers to be 3:1 (however, this ratio can vary depending on performance of the platform and analysis duration). To startup more postprocessing instances just start more instances of ``drak-postprocess@`` service. By default only 1 is present, so be sure to scale it accordingly to your needs.

The following command will start second postprocessing worker.

.. code-block:: console

  systemctl enable --now drak-postprocess@2
