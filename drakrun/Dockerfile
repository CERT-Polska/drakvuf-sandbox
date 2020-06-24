FROM debian:10 as drakvuf

RUN apt-get update && \
    apt-get --quiet --yes install \
        build-essential \
        zlib1g-dev \
        libncurses5-dev \
        libssl-dev \
        python2.7-dev \
        xorg-dev \
        uuid-dev \
        libyajl-dev \
        libaio-dev \
        libglib2.0-dev \
        clang \
        libpixman-1-dev \
        pkg-config \
        flex \
        bison \
        gettext \
        acpica-tools \
        bin86 \
        bcc \
        liblzma-dev \
        libc6-dev-i386 \
        libnl-3-dev \
        ocaml-nox \
        libfindlib-ocaml-dev \
        markdown \
        transfig \
        pandoc \
        checkpolicy \
        wget \
        git \
        nasm
#        && \
#        apt-get autoremove -y && \
#        apt-get clean && \
#        rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*

COPY ./.git /build/.git
COPY ./drakvuf /build/drakvuf
COPY ./drakrun /build/drakrun



WORKDIR /build/drakvuf/xen
RUN ./configure
RUN make -j4 dist-tools
RUN make -j4 install-tools
RUN make -j4 dist-xen
RUN make -j4 install-xen

WORKDIR /build/drakvuf/xen/dist/install
RUN cp -r * /tmp

WORKDIR /build/drakvuf/libvmi/build
#
# TODO move up
RUN apt-get install -y cmake libjson-c-dev

RUN cmake -DENABLE_FILE=0 -DENABLE_KVM=0 -DENABLE_BAREFLANK=0 .. && make -j4
RUN make install
RUN make DESTDIR=/tmp install

WORKDIR /build/drakvuf

RUN apt-get install -y wget git bcc bin86 gawk bridge-utils iproute2 libcurl4-openssl-dev bzip2 libpci-dev build-essential make gcc clang libc6-dev libc6-dev-i386 linux-libc-dev zlib1g-dev libncurses5-dev patch libvncserver-dev libssl-dev libsdl-dev iasl libbz2-dev e2fslibs-dev git-core uuid-dev ocaml libx11-dev bison flex ocaml-findlib xz-utils gettext libyajl-dev libpixman-1-dev libaio-dev libfdt-dev cabextract libglib2.0-dev autoconf automake libtool libjson-c-dev libfuse-dev liblzma-dev autoconf-archive kpartx python3-dev python3-pip golang python-dev

RUN autoreconf -vi
RUN ./configure
RUN make -j4
RUN make DESTDIR=/tmp install

FROM python:3.8 as drakrun

RUN apt-get update && apt-get install -y  libjson-c3 libyajl2
COPY --from=drakvuf /tmp /
RUN ldconfig
