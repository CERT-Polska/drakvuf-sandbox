=============================
DRAKVUF Sandbox Documentation
=============================

DRAKVUF Sandbox is an automated black-box malware analysis system with DRAKVUF engine under the hood, which does not require an agent on guest OS.

This project provides you with a friendly web interface that allows you to upload suspicious files to be analyzed. Once the sandboxing job is finished, you can explore the analysis result through the mentioned interface and get insight whether the file is truly malicious or not.

Because it is usually pretty hard to set up a malware sandbox, this project also provides you with an installer app that would guide you through the necessary steps and configure your system using settings that are recommended for beginners. At the same time, experienced users can tweak some settings or even replace some infrastructure parts to better suit their needs.

.. toctree::
   :maxdepth: 2
   :caption: User guide
   
   usage/getting_started
   usage/optional_features
   usage/managing_snapshots
   usage/scaling
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


   
