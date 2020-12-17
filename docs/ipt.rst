===================
Using Intel Processor Trace Features (Experimental)
===================

Prerequisites
-------------

In order to use IPT features, you need a special version of `drakvuf-bundle` that could be fetched from `icedevml/drakvuf-bundle-ipt releases <https://github.com/icedevml/drakvuf-bundle-ipt/releases>`_.

This special bundle version contains the following modification with respect to normal setup:

* `Xen with custom patches <https://github.com/icedevml/xen/tree/ipt-patch-v7s>`_
* DRAKVUF built with `--enable-ipt`

After you install the special version of `drakvuf-bundle`, please go to `/etc/drakrun/config.ini`, set `enable_ipt = 1` and restart drakrun services.

Your analyses should now contain additional artifacts called `execframe.log`, `pagefault.log` and `ipt.zip`. This data can be further processed by the analyst.


Install required extra dependencies
-----------------------------------

In order to analyze IPT data streams, you need to install `libipt`, `xed`, `ptdump` (modified) and `ptxed`.

.. code-block :: console

  rm -rf /tmp/iptbuild
  mkdir /tmp/iptbuild
  cd /tmp/iptbuild

  git clone https://github.com/icedevml/libipt.git
  git clone https://github.com/intelxed/xed.git
  git clone https://github.com/intelxed/mbuild.git

  cd xed
  ./mfile.py --share
  ./mfile.py --prefix=/usr/local install
  ldconfig

  cd ../libipt
  git checkout
  cmake -D PTDUMP=On -D PTXED=On .
  make install


Generate trace disassembly
--------------------------

1. Download the completed analysis from MinIO to your local hard drive
2. Execute drak-gen-ptxed --analysis . --cr3 <target_process_cr3> --vcpu 0
3. After few minutes it should start printing full trace disassembly of the targeted process
