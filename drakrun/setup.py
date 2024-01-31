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
    entry_points={
        "console_scripts": [
            "drakrun = drakrun.main:main",
            "draksetup = drakrun.draksetup:main",
            "drakpush = drakrun.drakpush:main",
            "drakpdb = drakrun.drakpdb:main",
            "drakplayground = drakrun.playground:main",
            "draktestd = drakrun.regression:RegressionTester.main"
            "draktest = drakrun.regression:RegressionTester.submit_main"
        ]
    },
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
