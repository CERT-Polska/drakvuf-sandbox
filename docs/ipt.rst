===================================================
Using Intel Processor Trace Features (Experimental)
===================================================

Enable IPT plugin in drakrun
----------------------------

1. In ``/etc/drakrun/config.toml``, add ``ipt`` plugin under ``[drakvuf_plugins]`` section ``__all__`` in order to enable IPT tracing.
2. In ``/etc/drakrun/scripts/cfg.template`` add a new entry: ``vmtrace_buf_kb = 8192``
3. Execute ``systemctl restart drakrun-worker@1`` (repeat for each drakrun instance if you have scaled them up).


Install required extra dependencies
-----------------------------------

In order to analyze IPT data streams, you need to install ``libipt``, ``xed``, ``ptdump`` (modified), ``ptxed`` and ``drak-ipt-blocks`` tools.

.. code-block :: console

  rm -rf /tmp/iptbuild
  mkdir /tmp/iptbuild
  cd /tmp/iptbuild

  git clone https://github.com/icedevml/libipt.git
  git clone https://github.com/intelxed/xed.git
  git clone https://github.com/intelxed/mbuild.git
  git clone https://github.com/gabime/spdlog.git
  git clone https://github.com/p-ranav/argparse.git -b v2.9
  git clone https://github.com/CERT-Polska/drakvuf-sandbox.git

  cd xed
  ./mfile.py --share
  ./mfile.py --prefix=/usr/local install
  ldconfig

  cd ../libipt
  git checkout
  cmake -D PTDUMP=On -D PTXED=On .
  make install
  
  cd ../spdlog
  cmake .
  make -j$(nproc) install

  cd ../argparse
  cmake .
  make -j$(nproc) install

  cd ../drakvuf-sandbox/drakrun/drakrun/tools/ipt
  cmake .
  make install


Generate trace disassembly
--------------------------

1. Perform an analysis with IPT plugin enabled
2. Download the completed analysis from MinIO to your local hard drive
3. Find CR3 of the target process you want to disassemble (hint: `syscall.log` will contain CR3 values)
4. Execute ``drak-ipt-disasm --analysis . --cr3 <target_process_cr3> --vcpu 0``
5. After few minutes it should start printing full trace disassembly of the targeted process
6. You can also try `--blocks` switch for `drak-ipt-disasm` to get a list of executed basic blocks for this process

**Example (executed basic blocks):**

.. code-block :: console

  # drak-ipt-disasm --analysis . --cr3 0x735bb000 --vcpu 0 --blocks
  [2021-04-19 23:47:41.717] [console] [info] Decoding
  { "event": "block_executed", "data": "0x7feff565088" }
  { "event": "block_executed", "data": "0x7feff75450f" }
  { "event": "block_executed", "data": "0x7feff754505" }
  { "event": "block_executed", "data": "0x7feff75450d" }
  { "event": "block_executed", "data": "0x7feff5656ac" }
  { "event": "block_executed", "data": "0x7feff5656dc" }
  { "event": "block_executed", "data": "0x7feff5656fb" }
  { "event": "block_executed", "data": "0x7feff565068" }
  { "event": "block_executed", "data": "0x7feff751530" }
  { "event": "block_executed", "data": "0x7feff751552" }
  ...


**Example (full usermode disassembly):**

.. code-block :: console

  # drak-ipt-disasm --analysis . --cr3 0x735bb000 --vcpu 0 | grep -v ptwrite | grep -v cbr
  [enabled]
  [exec mode: 64-bit]
  000007feff565088  movdqu xmmword ptr [rip+0x1b2b80], xmm0
  000007feff565090  ret
  000007feff75450f  add rbx, 0x8
  000007feff754513  cmp rbx, rdi
  000007feff754516  jb 0x7feff754505
  000007feff754505  mov rax, qword ptr [rbx]
  000007feff754508  test rax, rax
  000007feff75450b  jz 0x7feff75450f
  ...
