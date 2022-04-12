ARG IMAGE
FROM $IMAGE

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y wget curl python3 python3-dev python3-venv python3-pip debhelper devscripts lsb-release && \
    curl "http://snapshot.debian.org/archive/debian/20201029T084118Z/pool/main/d/dh-virtualenv/dh-virtualenv_1.2.1-1_all.deb" -o dh-virtualenv.deb && \
    curl -sL https://deb.nodesource.com/setup_14.x | bash - && \
    apt-get install -y nodejs && \
    python3 -m pip install pip && \
    pip3 install virtualenv==20.1.0 && \
    dpkg -i --ignore-depends=sphinx-rtd-theme-common ./dh-virtualenv.deb

COPY drakcore /build
WORKDIR /build
