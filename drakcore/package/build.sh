#!/bin/bash

# Directory with .deb files
OUTDIR=$(pwd)/out
# Base image for building
if [ "$BASEIMAGE" = "" ]
then
    BASEIMAGE=debian:buster
fi

# Current user - to make current user owner of output .deb files.
FILE_OWNER=$(id -u):$(id -g)

echo "Building $BASEIMAGE based image into $OUTDIR"
docker build -f drakcore/package/Dockerfile \
             --build-arg IMAGE=$BASEIMAGE \
             -t deb-build-web . && \
docker run --rm \
           -i \
           -v $OUTDIR:/out \
           deb-build-web \
           sh -c "package/find-python.sh && dpkg-buildpackage -us -uc -b && cp ../drakcore*.deb /out && chown -R $FILE_OWNER /out"

if [ $? -ne 0 ]; then echo Failed to build package ; exit 1 ; fi

echo Verifying package existence...
find $OUTDIR
