#!/bin/sh
# Helper script useful for manual splitting of drakvuf log file by plugin
# (normally done by a postprocess step)

[ $# -ne 1 ] && echo "Split DRAKVUF log by plugin. Usage:\n$0 [drakvuf log]" && exit 1
INPUT_FILE=$1

[ -f $INPUT_FILE ] || (echo "File not found!" && exit 1)

PLUGINS=$(jq -r "[ inputs.Plugin ] | unique | .[]" $INPUT_FILE)

echo "Plugins found: ${PLUGINS}"

for plugin in $PLUGINS; do
        FILENAME=${plugin}.log

        echo Writing $FILENAME...
        jq -c "select(.Plugin == \"${plugin}\")" $INPUT_FILE > $FILENAME
done
