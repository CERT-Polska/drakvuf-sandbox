#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

version = {}
with open("drakcore/version.py") as f:
    exec(f.read(), version)

setup(
    name="drakcore",
    version=version['__version__'],
    description="DRAKVUF Sandbox Core",
    package_dir={"drakcore": "drakcore"},
    packages=["drakcore", "drakcore.postprocess"],
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    scripts=['drakcore/bin/drak-system',
             'drakcore/bin/drak-config-setup',
             'drakcore/bin/drak-postprocess',
             'drakcore/bin/drak-healthcheck',
             'drakcore/bin/drak-vncpasswd',
             'drakcore/bin/drak-upgrade-db',
             'drakcore/bin/drak-ipt-disasm',
             'drakcore/bin/drak-ipt-filter'],
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
