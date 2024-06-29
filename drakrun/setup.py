#!/usr/bin/env python

import os
from setuptools import find_packages, setup

version_globals = {}
with open("drakrun/version.py") as f:
    exec(f.read(), version_globals)

version = version_globals["__version__"]
if os.getenv("DRAKRUN_VERSION_TAG"):
    version = version + "+" + os.getenv("DRAKRUN_VERSION_TAG")

setup(
    name="drakrun",
    version=version,
    description="DRAKRUN",
    package_dir={"drakrun": "drakrun"},
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "drakrun = drakrun.main:DrakrunKarton.main",
            "drakstart = drakrun.analyzer:main",
            "drakpostprocess = drakrun.postprocess:main",
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
