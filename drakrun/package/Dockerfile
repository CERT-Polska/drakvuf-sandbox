ARG IMAGE
FROM $IMAGE

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    wget curl python3 python3-pip python3-venv debhelper devscripts \
    libpixman-1-0 libpng16-16 libfdt1 libglib2.0-dev 'libjson-c[34]' libyajl2 libaio1 lsb-release && \
    if [ $(apt-cache search --names-only '^python3\.8$' | wc -l) -ne 0 ]; then apt-get install -y python3.8 python3.8-dev python3.8-venv ; else apt-get install -y python3.7 python3.7-dev python3.7-venv ; fi && \
    curl "http://snapshot.debian.org/archive/debian/20201031T220724Z/pool/main/d/dh-virtualenv/dh-virtualenv_1.2.2-1_all.deb" -o dh-virtualenv.deb && \
    pip3 install virtualenv==20.1.0 && \
    dpkg -i --ignore-depends=sphinx-rtd-theme-common ./dh-virtualenv.deb

RUN wget -O drakvuf.deb "https://debs.icedev.pl/manual/drakvuf-bundle/$(lsb_release -cs)/drakvuf-bundle-0.7-git20200501075508+0f828ce-1.deb" && \
    dpkg -i ./drakvuf.deb

COPY drakrun /build
WORKDIR /build
