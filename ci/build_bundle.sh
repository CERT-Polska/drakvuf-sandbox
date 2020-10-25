#!/bin/bash

INSTALL_PATH=/build/usr
mkdir -p $INSTALL_PATH

mc stat cache/debs/drakvuf-bundle-${DRAKVUF_COMMIT}.deb
if [ $? -eq 0 ]; then
    echo "Package already exists. Skipping..."
    exit 0
fi

set -e

# Build Xen
pushd drakvuf/xen

./configure --prefix=/usr --enable-githttp --disable-pvshim > /dev/null 2>&1
make -j$(nproc) dist > /dev/null 2>&1
echo "Running Xen's make install-xen..."
make -j$(nproc) install-xen
echo "Running Xen's make install-tools..."
make -j$(nproc) install-tools

mv dist/install /dist-xen
popd
# Build DRAKVUF
mkdir -p drakvuf/libvmi/build

# Build LibVMI
pushd drakvuf/libvmi/build
cmake .. -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH \
         -DENABLE_FILE=OFF \
         -DENABLE_LINUX=OFF \
         -DENABLE_FREEBSD=OFF \
         -DENABLE_KVM=OFF \
         -DENABLE_BAREFLANK=OFF
make -j$(nproc)
make install
ldconfig
popd

# Package DRAKVUF and Xen
pushd drakvuf
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$INSTALL_PATH/lib" && \
export C_INCLUDE_PATH="$INSTALL_PATH/include" && \
export CPLUS_INCLUDE_PATH="$INSTALL_PATH/include" && \
export PKG_CONFIG_PATH="$INSTALL_PATH/lib/pkgconfig/" && \
export LDFLAGS="-L$INSTALL_PATH/lib" && \
export CFLAGS="-I$INSTALL_PATH/include" && \
autoreconf -vif
./configure --prefix=$INSTALL_PATH --enable-debug
make -j$(nproc)
make install

# Build dwarf2json
sh -c "cd dwarf2json && /usr/local/go/bin/go build"

mkdir /out
sh ./package/mkdeb
popd


mc cp /out/drakvuf-bundle*.deb "cache/debs/drakvuf-bundle-$DRAKVUF_COMMIT.deb"
