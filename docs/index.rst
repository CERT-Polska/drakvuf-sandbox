=============================
DRAKVUF Sandbox documentation
=============================

DRAKVUF Sandbox is an automated black-box malware analysis system with DRAKVUF engine under the hood, which does not require an agent on guest OS.

This project provides you with a friendly web interface that allows you to upload suspicious files to be analyzed. Once the sandboxing job is finished, you can explore the analysis result through the mentioned interface and get insight whether the file is truly malicious or not.

Because it is usually pretty hard to set up a malware sandbox, this project also comes with installation toolkit that would help you get through the necessary steps.

It's highly recommended to have a basic knowledge about Xen hypervisor that would help you debug issues that may depend on your hardware.

.. toctree::
   :maxdepth: 2
   :caption: User guide
   
   usage/getting_started
   usage/optional_features
   usage/managing_snapshots
   usage/troubleshooting
   usage/upgrading
   usage/integration


   understanding_sandbox
   
.. toctree::
   :maxdepth: 2
   :caption: Developer guide

   sandbox_development
   regression_testing

.. toctree::
   :maxdepth: 1
   :caption: Misc
   
   faq
   drakpdb
   ipt


   
