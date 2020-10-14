# DRAKVUF Sandbox
[![Slack](https://img.shields.io/badge/Slack-KVM--VMI-important)](https://kvm-vmi.slack.com) [![Build Status](https://drone.icedev.pl/api/badges/CERT-Polska/drakvuf-sandbox/status.svg)](https://drone.icedev.pl/CERT-Polska/drakvuf-sandbox) [![Documentation Status](https://readthedocs.org/projects/drakvuf-sandbox/badge/?version=latest)](https://drakvuf-sandbox.readthedocs.io/en/latest/?badge=latest)

DRAKVUF Sandbox is an automated black-box malware analysis system with [DRAKVUF](https://drakvuf.com/) engine under the hood, which does not require an agent on guest OS.

This project provides you with a friendly web interface that allows you to upload suspicious files to be analyzed. Once the sandboxing job is finished, you can explore the analysis result through the mentioned interface and get insight whether the file is truly malicious or not.

Because it is usually pretty hard to set up a malware sandbox, this project also provides you with an installer app that would guide you through the necessary steps and configure your system using settings that are recommended for beginners. At the same time, experienced users can tweak some settings or even replace some infrastructure parts to better suit their needs.

![DRAKVUF Sandbox - Analysis view](.github/screenshots/sandbox.png)

## Supported hardware & software

In order to run DRAKVUF Sandbox, your setup must fullfill all of the listed requirements:

* Processor: Intel processor with VT-x and EPT features.
* Host system: Debian 10 Buster/Ubuntu 18.04 Bionic/Ubuntu 20.04 Focal with at least 2 core CPU and 5 GB RAM, running GRUB as bootloader.
* Guest system: Windows 7 (x64), Windows 10 (x64; experimental support)

Nested virtualization:

* KVM **does** work, however it is considered experimental. If you experience any bugs, please report them to us for further investigation.
* Due to lack of exposed CPU features, hosting DRAKVUF Sandbox in the cloud is **not** supported (although it might change in the future).
* Hyper-V does **not** work.
* Xen **does** work out of the box.
* VMware Workstation Player **does** work, but you need to check Virtualize EPT option for a VM; Intel processor with EPT still required.


## Installation
[Here](https://github.com/CERT-Polska/drakvuf-sandbox/releases) you can find the latest releases.

See the docs for the [installation guide](https://drakvuf-sandbox.readthedocs.io/en/latest/usage/getting_started.html).

## Maintainers/authors

Feel free to contact us if you have any questions or comments.

**General contact email: drakvuf@cert.pl** (fastest response)

This project is authored by:

* Michał Leszczyński ([@icedevml](https://github.com/icedevml)) - monk@cert.pl
* Adam Kliś ([@BonusPlay](https://github.com/BonusPlay)) - bonus@cert.pl
* Hubert Jasudowicz ([@chivay](https://github.com/chivay)) - chivay@cert.pl
* Konstanty Cieśliński ([@kscieslinski](https://github.com/kscieslinski)) - konstanty.cieslinski@cert.pl

You can also reach us on IRC - [#drakvuf-sandbox@irc.freenode.net](https://webchat.freenode.net/#drakvuf-sandbox).

If you have any questions about [DRAKVUF](https://drakvuf.com/) engine itself, contact tamas@tklengyel.com

## CEF Notice

![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/wp-content/uploads/2019/02/en_horizontal_cef_logo-1.png)
