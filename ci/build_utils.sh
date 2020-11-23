function build_xen() {
    # Expects the cwd to be Xen repository
    PREFIX=$1

    ./configure --prefix=$PREFIX --enable-githttp --disable-pvshim > /dev/null 2>&1
    make -j$(nproc) dist > /dev/null 2>&1
    make -j$(nproc) install-xen
    make -j$(nproc) install-tools
}

function build_libvmi() {
    # Expects the cwd to be libvmi repository
    PREFIX=$1

    mkdir -p $(pwd)/build
    cd build
    cmake .. -DCMAKE_INSTALL_PREFIX=$PREFIX \
             -DENABLE_FILE=OFF \
             -DENABLE_LINUX=OFF \
             -DENABLE_FREEBSD=OFF \
             -DENABLE_KVM=OFF \
             -DENABLE_BAREFLANK=OFF
    make -j$(nproc)
    make install
    ldconfig
}

function build_drakvuf() {
    # Expects the cwd to be drakvuf repository
    PREFIX=$1

    export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$PREFIX/lib" && \
    export C_INCLUDE_PATH="$PREFIX/include" && \
    export CPLUS_INCLUDE_PATH="$PREFIX/include" && \
    export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig/" && \
    export LDFLAGS="-L$PREFIX/lib" && \
    export CFLAGS="-I$PREFIX/include" && \
    autoreconf -vif
    ./configure --prefix=$PREFIX --enable-debug
    make -j$(nproc)
    make install
}
