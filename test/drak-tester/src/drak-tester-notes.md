compilation:
```sh
cl /EHsc src/drakvuf_dump_tester.cpp src/utils/drakvuf_tester_utils.cpp /Isrc/utils /Fobin\ /Febin\drakvuf_tester.exe /std:c++latest

cl /DDEBUG /EHsc src/drakvuf_dump_tester.cpp src/utils/drakvuf_tester_utils.cpp /Isrc/utils /Fobin\ /Febin\drakvuf_tester.exe /std:c++latest
```

add `/DDEBUG` to set `DEBUG` variable.