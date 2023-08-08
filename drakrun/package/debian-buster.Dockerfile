FROM debian:buster

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    wget curl python2.7 python3 python3-pip python3-venv debhelper devscripts libc6-dev-i386 \
    libpixman-1-0 libpng16-16 libfdt1 libglib2.0-dev 'libjson-c[34]' libyajl2 libaio1 lsb-release dh-virtualenv

# Install drakvuf bundle for libvmi headers
RUN wget -O drakvuf.deb "https://github.com/tklengyel/drakvuf/releases/download/1.0/debian_10-slim_drakvuf-bundle-1.0-git20221220221439+068b10f-1-generic.deb" && \
    dpkg -i ./drakvuf.deb && \
    cd /opt && \
    git clone https://xenbits.xen.org/git-http/xtf.git && \
    cd xtf && \
    git checkout 8ab15139728a8efd3ebbb60beb16a958a6a93fa1 && \
    make PYTHON=python2.7 -j4

COPY . /build/
WORKDIR /build

RUN PYTHON_BIN=python3.7 dpkg-buildpackage -us -uc -b
