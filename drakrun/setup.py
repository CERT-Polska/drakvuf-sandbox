#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name="drakrun",
    version="0.8.0",
    description="DRAKRUN",
    package_dir={"drakrun": "drakrun"},
    packages=["drakrun"],
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    scripts=['drakrun/py-scripts/drakrun', 'drakrun/py-scripts/draksetup', 'drakrun/py-scripts/drakpush'],
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
