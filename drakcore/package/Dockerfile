ARG IMAGE
FROM $IMAGE

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y wget curl python3 python3-venv python3-pip dh-virtualenv debhelper devscripts && \
    curl -sL https://deb.nodesource.com/setup_13.x | bash - && \
    apt-get install -y nodejs

COPY drakcore /build
WORKDIR /build
