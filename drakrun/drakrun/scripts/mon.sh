#!/bin/bash

KERNEL_PROFILE="$DRAK_LIB_DIR/profiles/kernel.json"
INJECTION_PID=$($DRAK_MAIN_DIR/tools/get-explorer-pid "vm-$1" "$KERNEL_PROFILE")

ulimit -c unlimited
ulimit -m 1073741824
# TODO configurable timeout
timeout 660 drakvuf -o json -x poolmon -x objmon -j 5 -t 600 -i "$INJECTION_PID" -d "vm-$1" --dll-hooks-list $DRAK_ETC_DIR/hooks.txt --memdump-dir "$(pwd)/dumps" -r "$KERNEL_PROFILE" -e 'D:\run.bat' > drakmon.log

EXIT_CODE=$?

if [ "$EXIT_CODE" != 0 ]
then
    echo Drakmon failed with code $EXIT_CODE
    exit $EXIT_CODE
fi
