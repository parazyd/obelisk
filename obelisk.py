#!/usr/bin/env python3
# Copyright (C) 2020-2021 Ivan J. <parazyd@dyne.org>
#
# This file is part of obelisk
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License version 3
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import asyncio
import sys
from argparse import ArgumentParser
from configparser import RawConfigParser, NoSectionError
from logging import getLogger, FileHandler, Formatter, StreamHandler, DEBUG
from os.path import join
from tempfile import gettempdir

from electrumobelisk.protocol import ElectrumProtocol, VERSION

# Used for destructor/cleanup
PROTOCOL = None


def logger_config(log, config):
    """Setup logging"""
    fmt = Formatter(
        config.get(
            "obelisk",
            "log_format",
            fallback="%(asctime)s\t%(levelname)s\t%(message)s",
        ))
    logstream = StreamHandler()
    logstream.setFormatter(fmt)
    logstream.setLevel(
        config.get("obelisk", "log_level_stdout", fallback="DEBUG"))
    log.addHandler(logstream)
    filename = config.get("obelisk", "log_file_location", fallback="")
    if len(filename.strip()) == 0:
        filename = join(gettempdir(), "obelisk.log")
    logfile = FileHandler(
        filename,
        mode=("a" if config.get("obelisk", "append_log", fallback="false") else
              "w"),
    )
    logfile.setFormatter(fmt)
    logfile.setLevel(DEBUG)
    log.addHandler(logfile)
    log.setLevel(DEBUG)
    return log, filename


async def run_electrum_server(config, chain):
    """Server coroutine"""
    log = getLogger("obelisk")
    host = config.get("obelisk", "host")
    port = int(config.get("obelisk", "port"))

    broadcast_method = config.get("obelisk",
                                  "broadcast_method",
                                  fallback="tor")
    tor_host = config.get("obelisk", "tor_host", fallback="localhost")
    tor_port = int(config.get("obelisk", "tor_port", fallback=9050))

    endpoints = {}
    endpoints["query"] = config.get("obelisk", "query")
    endpoints["heart"] = config.get("obelisk", "heart")
    endpoints["block"] = config.get("obelisk", "block")
    endpoints["trans"] = config.get("obelisk", "trans")

    server_cfg = {}
    server_cfg["torhostport"] = (tor_host, tor_port)
    server_cfg["broadcast_method"] = broadcast_method
    server_cfg["server_hostname"] = "localhost"  # TODO: <- should be public?
    server_cfg["server_port"] = port

    global PROTOCOL
    PROTOCOL = ElectrumProtocol(log, chain, endpoints, server_cfg)

    server = await asyncio.start_server(PROTOCOL.recv, host, port)
    async with server:
        await server.serve_forever()


def main():
    """Main orchestration"""
    parser = ArgumentParser(description=f"obelisk {VERSION}")
    parser.add_argument("config_file", help="Path to config file")
    args = parser.parse_args()

    try:
        config = RawConfigParser()
        config.read(args.config_file)
        config.options("obelisk")
    except NoSectionError:
        print(f"error: Invalid config file {args.config_file}")
        return 1

    log = getLogger("obelisk")
    log, logfilename = logger_config(log, config)
    log.info(f"Starting obelisk {VERSION}")
    log.info(f"Logging to {logfilename}")

    chain = config.get("obelisk", "chain")
    if chain not in ("mainnet", "testnet"):
        log.error("chain is not 'mainnet' or 'testnet'")
        return 1

    try:
        asyncio.run(run_electrum_server(config, chain))
    except KeyboardInterrupt:
        print("\r", end="")
        log.debug("Caught KeyboardInterrupt, exiting...")
        if PROTOCOL:
            asyncio.run(PROTOCOL.stop())
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
