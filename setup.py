#!/usr/bin/env python3
from setuptools import setup

from obelisk.protocol import VERSION

setup(
    name="Obelisk",
    version=VERSION,
    packages=["obelisk"],
    package_dir={
        "obelisk": "obelisk",
    },
    install_requires=["pyzmq"],
    scripts=["obelisk/obelisk"],
    description="Electrum server using libbitcoin and zmq as backend",
    author="Ivan J.",
    author_email="parazyd@dyne.org",
    license="AGPL-3",
    url="https://github.com/parazyd/obelisk",
    long_description="""Electrum server using libbitcoin and zmq as backend""",
    include_package_data=True,
    data_files=[("share/doc/obelisk", ["README.md", "res/obelisk.cfg"])],
)
