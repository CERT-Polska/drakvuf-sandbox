function build_xen() {
    PREFIX=$1
    # Expects the cwd to be Xen repository
    ./configure --prefix=$PREFIX --enable-githttp --disable-pvshim
    make -j$(nproc) dist
    make -j$(nproc) install-xen
    make -j$(nproc) install-tools
}

function build_libvmi() {
    PREFIX=$1
    mkdir -p build && cd build
    cmake .. -DCMAKE_INSTALL_PREFIX=$PREFIX \
             -DENABLE_FILE=OFF \
             -DENABLE_LINUX=OFF \
             -DENABLE_FREEBSD=OFF \
             -DENABLE_KVM=OFF \
             -DENABLE_BAREFLANK=OFF \
             -DENV_DEBUG=ON \
             -DCMAKE_BUILD_TYPE=RelWithDebInfo
    make -j$(nproc)
    make install
}

function build_drakvuf() {
    PREFIX=$1
    export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$PREFIX/lib"
    export C_INCLUDE_PATH="$PREFIX/include"
    export CPLUS_INCLUDE_PATH="$PREFIX/include"
    export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig/"
    export LDFLAGS="-L$PREFIX/lib"
    export CFLAGS="-I$PREFIX/include"
    autoreconf -vif
    ./configure --prefix=$PREFIX --enable-debug --enable-ipt
    make -j$(nproc)
    make install
}
