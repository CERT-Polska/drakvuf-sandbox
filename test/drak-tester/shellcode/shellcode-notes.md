compilation:
```sh
# from powershell
nasm -f win64 -o shellcode-test.obj shellcode-base.asm

# from dev command prompt
link shellcode-base.obj /subsystem:console /entry:main /out:shellcode-base.exe
```
modify:
- append bytes with application name to run
    - "\x63\x61\x6C\x63\x2E\x65\x78\x65\x00\x00" for "calc.exe"


