#!/bin/bash

# Import utils
SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`
source $SCRIPTPATH/build_utils.sh


mc stat cache/debs/drakvuf-bundle-${DRAKVUF_COMMIT}.deb
if [ $? -eq 0 ]; then
    echo "Package already exists. Skipping..."
    exit 0
fi

set -e

INSTALL_PATH=/build/usr
mkdir -p $INSTALL_PATH

# Build Xen
pushd drakvuf/xen
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

mc cp /out/drakvuf-bundle*.deb "cache/debs/drakvuf-bundle-$DRAKVUF_COMMIT.deb"
