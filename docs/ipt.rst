===================================================
Using Intel Processor Trace Features (Experimental)
===================================================

Install required extra dependencies
-----------------------------------

In order to analyze IPT data streams, you need to install ``libipt``, ``xed``, ``ptdump`` (modified) and ``ptxed``.

.. code-block :: console

  $ rm -rf /tmp/iptbuild
  $ mkdir /tmp/iptbuild
  $ cd /tmp/iptbuild

  $ git clone https://github.com/icedevml/libipt.git
  $ git clone https://github.com/intelxed/xed.git
  $ git clone https://github.com/intelxed/mbuild.git

  $ cd xed
  $ ./mfile.py --share
  $ ./mfile.py --prefix=/usr/local install
  $ ldconfig

  $ cd ../libipt
  $ git checkout
  $ cmake -D PTDUMP=On -D PTXED=On .
  $ make install


Generate trace disassembly
--------------------------

1. Download the completed analysis from MinIO to your local hard drive
2. Execute ``drak-gen-ptxed --analysis . --cr3 <target_process_cr3> --vcpu 0``
3. After few minutes it should start printing full trace disassembly of the targeted process
