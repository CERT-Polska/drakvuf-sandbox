#!/bin/bash

# Import utils
SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`
source $SCRIPTPATH/build_utils.sh

function help() {
    echo "Usage: "
    echo "$0 [drakvuf-sandbox tree] [patch directory]"
    echo
    echo "Patch dir is expected to contain qemu/ and xen/"
    echo "Each of them containts patch files for appropriate subsystems"
}

if [ $# -ne "2" ]; then
    help
    exit 1
fi


SANDBOX_DIR=$1

# Don't clobber local repository
cp -ra $SANDBOX_DIR /build
SANDBOX_DIR=/build

PATCH_DIR=$2
XEN_DIR=$SANDBOX_DIR/drakvuf/xen

set -e

function setup_repository () {
    pushd $XEN_DIR
    # Configure Xen. We have to do this, otherwise pulling QEMU fails
    # and we won't be able to patch it
    echo "[+] Configuring Xen"
    ./configure --prefix=/usr --enable-githttp --disable-pvshim

    # Pull QEMU and SeaBIOS (we have to patch it)
    make subtree-force-update
    popd

    echo "[+] Patching QEMU"
    QEMU_PATCH_DIR=$PATCH_DIR/qemu
    if [ -d $QEMU_PATCH_DIR ]; then
        pushd $XEN_DIR/tools/qemu-xen-dir-remote
        git apply $QEMU_PATCH_DIR/*.patch
        popd
    fi

    echo "[+] Patching Xen"
    XEN_PATCH_DIR=$PATCH_DIR/xen
    if [ -d $XEN_PATCH_DIR ]; then
        pushd $XEN_DIR
        git apply $XEN_PATCH_DIR/*.patch
        popd
    fi

    echo "[+] Done patching"
}

echo "[+] Setting up repository"
setup_repository

INSTALL_PATH=/build/drakvuf/usr
mkdir -p $INSTALL_PATH

echo "[+] Building Xen"
pushd $XEN_DIR
build_xen /usr
mv dist/install /dist-xen
popd

echo "[+] Building LibVMI"
pushd $SANDBOX_DIR/drakvuf/libvmi
build_libvmi $INSTALL_PATH
popd

echo "[+] Building DRAKVUF"
pushd $SANDBOX_DIR/drakvuf
build_drakvuf $INSTALL_PATH
popd

echo "[+] Building dwarf2json"
pushd $SANDBOX_DIR/drakvuf/dwarf2json
/usr/local/go/bin/go build
popd

echo "[+] Packaging DRAKVUF"
mkdir -p /out
pushd $SANDBOX_DIR/drakvuf

# Remove volatility3
sed -i '/volatility3/d' ./package/mkdeb
# Change drakvuf build dir
sed -i 's/\/build/\/build\/drakvuf/g' ./package/mkdeb

sh ./package/mkdeb
popd
