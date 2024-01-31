#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

version = {}
with open("drakrun/version.py") as f:
    exec(f.read(), version)

setup(
    name="drakrun",
    version=version["__version__"],
    description="DRAKRUN",
    package_dir={"drakrun": "drakrun"},
    packages=["drakrun", "drakrun.lib", "drakrun.test"],
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
