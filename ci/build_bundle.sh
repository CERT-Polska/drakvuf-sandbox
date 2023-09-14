#!/bin/bash

# Import utils
SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`
source $SCRIPTPATH/build_utils.sh

set -e

INSTALL_PATH=/build/drakvuf/usr
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
popd

# Package DRAKVUF
pushd drakvuf
mkdir /out

# remove volatility3
sed -i '/volatility3/d' ./package/mkdeb
# change drakvuf build dir
sed -i 's/\/build/\/build\/drakvuf/g' ./package/mkdeb

DRAKVUFVERSION=$(./scripts/version.sh --dev)
XENVERSION=$(./xen/version.sh --full ./xen/xen/Makefile)

sh ./package/mkdeb "$DRAKVUFVERSION" "$XENVERSION"
popd
