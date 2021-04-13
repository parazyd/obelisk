obelisk
=======

![obelisk](res/obelisk.png)

A **work-in-progress** implementation of an
[Electrum](https://electrum.org) server using
[libbitcoin](https://libbitcoin.info) as a backend.

[![Tests](https://github.com/parazyd/obelisk/actions/workflows/py.yaml/badge.svg)](https://github.com/parazyd/obelisk/actions/workflows/py.yaml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

Please consider donating to support development:

```
bc1q7an9p5pz6pjwjk4r48zke2yfaevafzpglg26mz
```


TODO
----

* Better (and more) error handling
* More testing
* git grep -E "TODO:|BUG:"


Dependencies
------------

* Python 3
* pyzmq (python3-zmq or dev-python/pyzmq)


Usage
-----

Set up [obelisk.cfg](res/obelisk.cfg), and run

```
./run_obelisk ./res/obelisk.cfg
```

Obelisk can use either public libbitcoin v4 servers, or your local
libbitcoin-server if you have a running installation. Currently,
**only testnet v4 public servers are available**, and they're set up
as default in the configuration file.

Obelisk can also be installed with setuptools:

```
python3 setup.py install --user
```
