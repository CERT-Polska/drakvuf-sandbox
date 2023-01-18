#!/bin/bash

# Import utils
SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`
source $SCRIPTPATH/build_utils.sh

mc stat cache/debs/drakvuf-bundle-${DRAKVUF_COMMIT}.deb
drak_exists=$?
mc stat cache/debs/xen-hypervisor-${DRAKVUF_COMMIT}.deb
xen_exists=$?
if [ $drak_exists -eq 0 ] && [ $xen_exists -eq 0 ] ; then
    echo "Packages exist. Skipping..."
    exit 0
fi

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

sh ./package/mkdeb
popd

mc cp /out/drakvuf-bundle*.deb "cache/debs/drakvuf-bundle-$DRAKVUF_COMMIT.deb"
mc cp /out/xen-hypervisor*.deb "cache/debs/xen-hypervisor-$DRAKVUF_COMMIT.deb"
