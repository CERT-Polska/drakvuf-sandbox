#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name="drakcore",
    version="0.1.0",
    description="DRAKVUF Sandbox Core",
    package_dir={"drakcore": "drakcore"},
    packages=["drakcore"],
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    scripts=['drakcore/bin/drak-archiver', 'drakcore/bin/drak-system', 'drakcore/bin/drak-config-setup'],
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
