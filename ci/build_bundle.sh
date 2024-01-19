#!/bin/bash

# Import utils
SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`
source $SCRIPTPATH/build_utils.sh

set -e

# Usage of /build as root is required by DRAKVUF's mkdeb script
INSTALL_PATH=/build/usr
mkdir -p $INSTALL_PATH

# Build Xen
pushd drakvuf/xen
# We use /usr because LibVMI wants to see
# Xen headers. /dist-xen is used by DRAKVUF's mkdeb
build_xen /usr
mv dist/install /dist-xen
popd

# Build LibVMI
pushd drakvuf/libvmi
build_libvmi $INSTALL_PATH
popd

# Build DRAKVUF
pushd drakvuf
build_drakvuf $INSTALL_PATH
popd

# Build dwarf2json
pushd drakvuf/dwarf2json
/usr/local/go/bin/go build
mkdir -p /build/dwarf2json/
mv dwarf2json /build/dwarf2json/
popd

# Package DRAKVUF
pushd drakvuf
mkdir /out
sh ./package/mkdeb
popd
