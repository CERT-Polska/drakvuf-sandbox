from setuptools import setup, find_packages

setup(
    name='sandboxapi',
    version='0.1',
    description='Simple client-side API binding for DRAKVUF Sandbox',
    packages=find_packages(),
    install_requires=[
        'requests'
    ],
    entry_points={
        'console_scripts': ['sandboxcli=sandboxapi.cli:main'],
    }
)
