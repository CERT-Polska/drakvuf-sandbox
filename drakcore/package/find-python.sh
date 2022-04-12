#!/bin/bash

PYTHON_BIN=$(which python3.9 || which python3.8 || which python3.7)
PYTHON_PACK=$(basename "$PYTHON_BIN")

sed "s/{{PYTHON_PACKAGES}}/${PYTHON_PACK}, lib${PYTHON_PACK}/" package/control.template > debian/control
echo -n "$PYTHON_BIN" > package/python-bin

