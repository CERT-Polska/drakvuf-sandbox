#!/usr/bin/env python
from setuptools import setup

import os

version_path = os.path.join(os.path.dirname(__file__), "draklib/__version__.py")
version_info = {}
with open(version_path) as f:
    exec(f.read(), version_info)


setup(
    name="draklib",
    version=version_info["__version__"],
    description="Drakvuf-Sandbox shell utility for easy managing and debugging Drakvuf instance",
    packages=["draklib"],
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        'console_scripts': [
            'draksh=draklib.draksh.main:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python : 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7"
)
