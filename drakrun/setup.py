#!/usr/bin/env python
from setuptools import setup, find_packages

import os

version_path = os.path.join(os.path.dirname(__file__), "drakrun/__version__.py")
version_info = {}
with open(version_path) as f:
    exec(f.read(), version_info)

setup(
    name="drakrun",
    version=version_info["__version__"],
    description="Drakvuf Sandbox analysis runner",
    package_dir={"drakrun": "drakrun"},
    packages=find_packages(),
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        'console_scripts': [
            'drakrun=drakrun.drakrun:Drakrun.main',
            'draksetup=drakrun.utilities.draksetup:main',
            'drakpush=drakrun.utiltities.drakpush:main',
            'drakplayground=drakrun.utilities.playground:main',
            'draktestd=drakrun.utilities.regression:RegressionTester.main',
            'draktest=drakrun.utilities.regression:RegressionTester.submit_main',
            'drakpdb=drakrun.profile.drakpdb:main',
        ]
    },
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
