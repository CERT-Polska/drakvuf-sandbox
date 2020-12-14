#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name="drakcore",
    version="0.13.0",
    description="DRAKVUF Sandbox Core",
    package_dir={"drakcore": "drakcore"},
    packages=["drakcore", "drakcore.postprocess"],
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    scripts=['drakcore/bin/drak-archiver',
             'drakcore/bin/drak-system',
             'drakcore/bin/drak-config-setup',
             'drakcore/bin/drak-postprocess',
             'drakcore/bin/drak-healthcheck',
             'drakcore/bin/drak-vncpasswd',
             'drakcore/bin/drak-upgrade-db',
             'drakcore/bin/drak-gen-ptxed',
             'drakcore/bin/drak-ipt-filter'],
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
