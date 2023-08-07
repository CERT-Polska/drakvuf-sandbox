#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import os

version_path = os.path.join(os.path.dirname(__file__), "drakrun/__version__.py")
version_info = {}
with open(version_path) as f:
    exec(f.read(), version_info)

setup(
    name="drakrun",
    version=version_info["__version__"],
    description="DRAKRUN",
    package_dir={"drakrun": "drakrun"},
    packages=["drakrun", "drakrun.test"],
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    scripts=[
        "drakrun/py-scripts/drakrun",
        "drakrun/py-scripts/draksetup",
        "drakrun/py-scripts/drakpush",
        "drakrun/py-scripts/drakpdb",
        "drakrun/py-scripts/drakplayground",
        "drakrun/py-scripts/draktestd",
        "drakrun/py-scripts/draktest",
    ],
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
