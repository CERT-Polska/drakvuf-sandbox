#!/bin/bash

# Directory with .deb files
OUTDIR=$(pwd)/out
# Base image for building
if [ "$BASEIMAGE" = "" ]
then
    BASEIMAGE=debian-buster
fi

echo "Building $BASEIMAGE based image into $OUTDIR"
docker build -f drakrun/package/$BASEIMAGE.Dockerfile \
             -t deb-build . && \
docker run --rm \
           -v $OUTDIR:/out \
           deb-build \
           sh -c "cp ../drakrun*.deb /out"

if [ $? -ne 0 ]; then echo Failed to build package ; exit 1 ; fi

echo Packages created:
find $OUTDIR
