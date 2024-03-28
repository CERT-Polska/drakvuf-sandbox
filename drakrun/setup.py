#!/usr/bin/env python

from setuptools import find_packages, setup

version = {}
with open("drakrun/version.py") as f:
    exec(f.read(), version)

setup(
    name="drakrun",
    version=version["__version__"],
    description="DRAKRUN",
    package_dir={"drakrun": "drakrun"},
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "drakrun = drakrun.main:main",
            "draksetup = drakrun.draksetup:main",
            "drakpush = drakrun.drakpush:main",
            "drakpdb = drakrun.drakpdb:main",
            "drakplayground = drakrun.playground:main",
            "draktestd = drakrun.regression:RegressionTester.main",
            "draktest = drakrun.regression:RegressionTester.submit_main",
        ]
    },
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
