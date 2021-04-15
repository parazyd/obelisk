obelisk
=======

![obelisk](res/obelisk.png)

A **work-in-progress** implementation of an
[Electrum](https://electrum.org) server using
[libbitcoin](https://libbitcoin.info) as a backend.

[![Tests](https://github.com/parazyd/obelisk/actions/workflows/py.yaml/badge.svg)](https://github.com/parazyd/obelisk/actions/workflows/py.yaml)
[![CodeQL](https://github.com/parazyd/obelisk/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/parazyd/obelisk/actions/workflows/codeql-analysis.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

Please consider donating to support development:

```
bc1q7an9p5pz6pjwjk4r48zke2yfaevafzpglg26mz
```


TODO
----

* Better (and more) error handling
* More testing
* git grep -nE "TODO:|BUG:"


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


Development
-----------

The code is written to be short and concise. `run_obelisk` is the
entry point to start the server, but most of the actual logic is
in `obelisk/protocol.py` and `obelisk/zeromq.py`. `protocol.py`
implements the ElectrumX protocol, and `zeromq.py` implements the
libbitcoin side of things.

Before committing code, please run `./res/format_code.py` to format
the codebase to a certain code style. This scripts depends on `black`
and `yapf`.

It is also recommended to run the test suite and see if anything
fails:

```
python3 ./tests/test_electrum_protocol.py
```

You can chat about Obelisk on Freenode IRC, either `#electrum` or
`#libbitcoin`.
