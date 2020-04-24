#!/bin/bash

# Directory with .deb files
OUTDIR=$(pwd)/out
# Base image for building
BASEIMAGE=ubuntu:18.04
# Current user - to make current user owner of output .deb files.
FILE_OWNER=$(id -u):$(id -g)

echo "Building $BASEIMAGE based image into $OUTDIR"
docker build -f drakrun/package/Dockerfile \
             --build-arg IMAGE=$BASEIMAGE \
             -t deb-build . && \
docker run --rm \
           -it \
           -v $OUTDIR:/out \
           deb-build \
           sh -c "dpkg-buildpackage -us -uc -b && cp ../drakrun*.deb /out && chown -R $FILE_OWNER /out"

if [ $? -ne 0 ]; then echo Failed to build package ; exit 1 ; fi

echo Verifying package existence...
find $OUTDIR
