function build_xen() {
    PREFIX=$1
    # Expects the cwd to be Xen repository
    ./configure --prefix=$PREFIX --enable-githttp --disable-pvshim --enable-systemd --enable-ovmf
    echo CONFIG_EXPERT=y > xen/.config
    echo CONFIG_MEM_SHARING=y >> xen/.config
    make -C xen olddefconfig
    make -j$(nproc) dist-xen
    make -j$(nproc) dist-tools
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
    # Use clang as compiler, otherwise stuff doesn't build
    # with drakvuf xen_helpers breaking on -Werror-c++-compat
    export CC=clang
    export CXX=clang++
    autoreconf -vif
    ./configure --prefix=$PREFIX --enable-debug
    make -j$(nproc)
    make install
}
