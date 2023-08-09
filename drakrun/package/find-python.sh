#!/bin/bash

PYTHON_BIN_LINK=$(which python3)
PYTHON_BIN=$(readlink -f "$PYTHON_BIN_LINK")
PYTHON_PACK=$(basename "$PYTHON_BIN")

sed "s/{{PYTHON_PACKAGES}}/${PYTHON_PACK}/" package/control.template > debian/control
echo -n "$PYTHON_BIN" > package/python-bin
