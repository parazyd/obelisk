obelisk
=======

![obelisk](res/obelisk.png)

A **work-in-progress** implementation of an
[Electrum](https://electrum.org) server using
[libbitcoin](https://libbitcoin.info) as a backend.

![Tests](https://github.com/parazyd/obelisk/actions/workflows/py.yaml/badge.svg)

Please consider donating to support development:

```
bc1q7an9p5pz6pjwjk4r48zke2yfaevafzpglg26mz
```


TODO
----

* Better (and more) error handling
* More testing
* git grep -E "TODO:|BUG:"


Usage
-----

Set up [obelisk.cfg](res/obelisk.cfg), and run

```
./obelisk.py ./res/obelisk.cfg
```

Some kind of setuptools installation should be written eventually.


License
-------

obelisk is licensed [AGPL-3](LICENSE.md).
