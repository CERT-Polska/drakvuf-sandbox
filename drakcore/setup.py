#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name="drakcore",
    version="0.6.0",
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
             'drakcore/bin/drak-vncpasswd'],
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
