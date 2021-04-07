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
import json

from electrumobelisk.util import is_non_negative_integer, safe_hexlify
from electrumobelisk.zeromq import Client

VERSION = 0.0
DONATION_ADDR = "bc1q7an9p5pz6pjwjk4r48zke2yfaevafzpglg26mz"

BANNER = ("""
Welcome to obelisk

"Tools for the people"

obelisk is a server that uses libbitcoin-server as its backend.
Source code can be found at: https://github.com/parazyd/obelisk

Please consider donating: %s
""" % DONATION_ADDR)


class ElectrumProtocol(asyncio.Protocol):
    """TBD"""
    def __init__(self, log, chain, endpoints, server_cfg):
        self.log = log
        self.endpoints = endpoints
        self.server_cfg = server_cfg
        self.loop = asyncio.get_event_loop()
        # Consider renaming bx to something else
        self.bx = Client(log, endpoints, self.loop)

        if chain == "mainnet":
            self.genesis = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        elif chain == "testnet":
            self.genesis = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        else:
            raise ValueError(f"Invalid chain '{chain}'")

    async def recv(self, reader, writer):
        recv_buf = bytearray()
        while True:
            data = await reader.read(4096)
            if not data or len(data) == 0:
                self.log.debug("Received EOF, disconnect")
                return
            recv_buf.extend(data)
            lb = recv_buf.find(b"\n")
            if lb == -1:
                continue
            while lb != -1:
                line = recv_buf[:lb].rstrip()
                recv_buf = recv_buf[lb + 1:]
                lb = recv_buf.find(b"\n")
                try:
                    line = line.decode("utf-8")
                    query = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError) as err:
                    self.log.debug("Got error: %s", repr(err))
                    break
                self.log.debug("=> " + line)
                await self.handle_query(writer, query)

    async def _send_response(self, writer, result, nid):
        response = {"jsonrpc": "2.0", "result": result, "id": nid}
        writer.write(json.dumps(response).encode("utf-8"))
        await writer.drain()
        # writer.close()

    async def _send_error(self, writer, error, nid):
        response = {"jsonrpc": "2.0", "error": error, "id": nid}
        writer.write(json.dumps(response).encode("utf-8"))
        await writer.drain()
        # writer.close()

    async def _send_reply(self, writer, resp, query):
        """Wrap function for sending replies"""
        if "error" in resp:
            return await self._send_error(writer, resp["error"], query["id"])
        return await self._send_response(writer, resp["result"], query["id"])

    async def blockchain_block_header(self, query):
        self.log.debug("query: %s", query)
        if "params" not in query:
            return {"error": "malformed query"}
        # TODO: cp_height
        index = query["params"][0]
        cp_height = query["params"][1] if len(query["params"]) == 2 else 0

        if not is_non_negative_integer(index):
            return {"error": "invalid block height"}
        if not is_non_negative_integer(cp_height):
            return {"error": "invalid cp_height"}

        _ec, data = await self.bx.block_header(index)
        if _ec and _ec != 0:
            return {"error": "request corrupted"}
        return {"result": safe_hexlify(data)}

    async def handle_query(self, writer, query):  # pylint: disable=R0915,R0912,R0911
        """Electrum protocol method handlers"""
        # https://electrumx-spesmilo.readthedocs.io/en/latest/protocol-methods.html
        if "method" not in query:
            self.log.debug("No 'method' in query: %s", query)
            return
        if "id" not in query:
            self.log.debug("No 'id' in query: %s", query)
            return

        method = query["method"]

        if method == "blockchain.block.header":
            self.log.debug("blockchain.block.header")
            resp = await self.blockchain_block_header(query)
            return await self._send_reply(writer, resp, query)

        if method == "blockchain.block.headers":
            self.log.debug("blockchain.block.headers")
            return

        if method == "blockchain.estimatefee":
            self.log.debug("blockchain.estimatefee")
            return

        if method == "blockchain.headers.subscribe":
            self.log.debug("blockchain.headers.subscribe")
            return

        if method == "blockchain.relayfee":
            self.log.debug("blockchain.relayfee")
            return

        if method == "blockchain.scripthash.get_balance":
            self.log.debug("blockchain.scripthash.get_balance")
            return

        if method == "blockchain.scripthash.get_history":
            self.log.debug("blockchain.scripthash.get_history")
            return

        if method == "blockchain.scripthash.get_mempool":
            self.log.debug("blockchain.scripthash.get_mempool")
            return

        if method == "blockchain.scripthash.listunspent":
            self.log.debug("blockchain.scripthash.listunspent")
            return

        if method == "blockchain.scripthash.subscribe":
            self.log.debug("blockchain.scripthash.subscribe")
            return

        if method == "blockchain.scripthash.unsubscribe":
            self.log.debug("blockchain.scripthash.unsubscribe")
            return

        if method == "blockchain.transaction.broadcast":
            self.log.debug("blockchain.transaction.broadcast")
            return

        if method == "blockchain.transaction.get":
            self.log.debug("blockchain.transaction.get")
            return

        if method == "blockchain.transaction.get_merkle":
            self.log.debug("blockchain.transaction.get_merkle")
            return

        if method == "blockchain.transaction.id_from_pos":
            self.log.debug("blockchain.transaction.id_from_pos")
            return

        if method == "mempool.get_fee_histogram":
            self.log.debug("mempool.get_fee_histogram")
            return

        if method == "server.add_peer":
            self.log.debug("server.add_peer")
            return

        if method == "server.banner":
            self.log.debug("server.banner")
            return

        if method == "server.donation_address":
            self.log.debug("server.donation_address")
            return

        if method == "server.features":
            self.log.debug("server.features")
            return

        if method == "server.peers.subscribe":
            self.log.debug("server.peers.subscribe")
            return

        if method == "server.ping":
            self.log.debug("server.ping")
            return

        if method == "server.version":
            self.log.debug("server.version")
            return

        self.log.error("BUG? Unhandled method: '%s' query=%s", method, query)
        return
