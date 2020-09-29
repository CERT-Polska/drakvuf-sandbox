#!/bin/sh

mc stat cache/images/drak-ci-${DRAKVUF_COMMIT}.qcow2
if [ $? -eq 0 ]; then
    echo "Image already exists. Skipping..."
    exit 0
fi

set -e

packer build -var bundle_url=$MINIO_SERVER/debs/drakvuf-bundle-${DRAKVUF_COMMIT}.deb vmbase.json
qemu-img resize debian_base/drak-ci +50G

mc cp debian_base/drak-ci cache/images/drak-ci-${DRAKVUF_COMMIT}.qcow2

