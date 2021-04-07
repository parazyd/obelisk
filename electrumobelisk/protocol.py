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

from electrumobelisk.merkle import merkle_branch
from electrumobelisk.util import (
    is_boolean,
    is_hash256_str,
    is_non_negative_integer,
    safe_hexlify,
)
from electrumobelisk.zeromq import Client

VERSION = 0.0
SERVER_PROTO_MIN = "1.4"
SERVER_PROTO_MAX = "1.4.2"
DONATION_ADDR = "bc1q7an9p5pz6pjwjk4r48zke2yfaevafzpglg26mz"

BANNER = ("""
Welcome to obelisk

"Tools for the people"

obelisk is a server that uses libbitcoin-server as its backend.
Source code can be found at: https://github.com/parazyd/obelisk

Please consider donating: %s
""" % DONATION_ADDR)


class ElectrumProtocol(asyncio.Protocol):  # pylint: disable=R0904,R0902
    """TBD"""
    def __init__(self, log, chain, endpoints, server_cfg):
        self.log = log
        self.endpoints = endpoints
        self.server_cfg = server_cfg
        self.loop = asyncio.get_event_loop()
        # In spec, version shouldn't be called more than once
        self.version_called = False
        # Consider renaming bx to something else
        self.bx = Client(log, endpoints, self.loop)

        if chain == "mainnet":
            self.genesis = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        elif chain == "testnet":
            self.genesis = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        else:
            raise ValueError(f"Invalid chain '{chain}'")

        # https://electrumx-spesmilo.readthedocs.io/en/latest/protocol-methods.html
        self.methodmap = {
            "blockchain.block.header": self.blockchain_block_header,
            "blockchain.block.headers": self.blockchain_block_headers,
            "blockchain.estimatefee": self.blockchain_estimatefee,
            "blockchain.headers.subscribe": self.blockchain_headers_subscribe,
            "blockchain.relayfee": self.blockchain_relayfee,
            "blockchain.scripthash.get_balance":
            self.blockchain_scripthash_get_balance,
            "blockchain.scripthash.get_mempool":
            self.blockchain_scripthash_get_mempool,
            "blockchain.scripthash.listunspent":
            self.blockchain_scripthash_listunspent,
            "blockchain.scripthash.subscribe":
            self.blockchain_scripthash_subscribe,
            "blockchain.scripthash.unsubscribe":
            self.blockchain_scripthash_unsubscribe,
            "blockchain.transaction.broadcast":
            self.blockchain_transaction_broadcast,
            "blockchain.transaction.get": self.blockchain_transaction_get,
            "blockchain.transaction.get_merkle":
            self.blockchain_transaction_get_merkle,
            "blockchain.transaction.id_from_pos":
            self.blockchain_transaction_from_pos,
            "mempool.get_fee_histogram": self.mempool_get_fee_histogram,
            "server_add_peer": self.server_add_peer,
            "server.banner": self.server_banner,
            "server.donation_address": self.server_donation_address,
            "server.features": self.server_features,
            "server.peers.subscribe": self.server_peers_subscribe,
            "server.ping": self.server_ping,
            "server.version": self.server_version,
        }

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
        self.log.debug("<= %s", response)
        writer.write(json.dumps(response).encode("utf-8"))
        await writer.drain()
        # writer.close()

    async def _send_error(self, writer, error, nid):
        response = {"jsonrpc": "2.0", "error": error, "id": nid}
        self.log.debug("<= %s", response)
        writer.write(json.dumps(response).encode("utf-8"))
        await writer.drain()
        # writer.close()

    async def _send_reply(self, writer, resp, query):
        """Wrap function for sending replies"""
        if "error" in resp:
            return await self._send_error(writer, resp["error"], query["id"])
        return await self._send_response(writer, resp["result"], query["id"])

    async def handle_query(self, writer, query):  # pylint: disable=R0915,R0912,R0911
        """Electrum protocol method handlers"""
        if "method" not in query:
            self.log.debug("No 'method' in query: %s", query)
            return
        if "id" not in query:
            self.log.debug("No 'id' in query: %s", query)
            return

        method = query["method"]
        func = self.methodmap.get(method)
        if not func:
            self.log.error("Unhandled method %s, query=%s", method, query)
            return
        resp = await func(query)
        return await self._send_reply(writer, resp, query)

    async def blockchain_block_header(self, query):
        if "params" not in query or len(query["params"]) < 1:
            return {"error": "malformed query"}
        # TODO: cp_height
        index = query["params"][0]
        cp_height = query["params"][1] if len(query["params"]) == 2 else 0

        if not is_non_negative_integer(index):
            return {"error": "invalid block height"}
        if not is_non_negative_integer(cp_height):
            return {"error": "invalid cp_height"}

        _ec, data = await self.bx.fetch_block_header(index)
        if _ec and _ec != 0:
            self.log.debug("Got error: {_ec}")
            return {"error": "request corrupted"}
        return {"result": safe_hexlify(data)}

    async def blockchain_block_headers(self, query):
        if "params" not in query or len(query["params"]) < 2:
            return {"error": "malformed query"}
        # Electrum doesn't allow max_chunk_size to be less than 2016
        # gopher://bitreich.org/9/memecache/convenience-store.mkv
        # TODO: cp_height
        max_chunk_size = 2016
        start_height = query["params"][0]
        count = query["params"][1]

        if not is_non_negative_integer(start_height):
            return {"error": "invalid start_height"}
        if not is_non_negative_integer(count):
            return {"error": "invalid count"}

        count = min(count, max_chunk_size)
        headers = bytearray()
        for i in range(count):
            _ec, data = await self.bx.fetch_block_header(i)
            if _ec and _ec != 0:
                self.log.debug("Got error: {_ec}")
                return {"error": "request corrupted"}
            headers.extend(data)

        resp = {
            "hex": safe_hexlify(headers),
            "count": len(headers) // 80,
            "max": max_chunk_size,
        }
        return {"result": resp}

    async def blockchain_estimatefee(self, query):  # pylint: disable=W0613
        # Help wanted
        return {"result": -1}

    async def blockchain_headers_subscribe(self, query):
        return

    async def blockchain_relayfee(self, query):  # pylint: disable=W0613
        # Help wanted
        return {"result": 0.00001}

    async def blockchain_scripthash_get_balance(self, query):
        return

    async def blockchain_scripthash_get_mempool(self, query):
        return

    async def blockchain_scripthash_listunspent(self, query):
        return

    async def blockchain_scripthash_subscribe(self, query):
        return

    async def blockchain_scripthash_unsubscribe(self, query):
        return

    async def blockchain_transaction_broadcast(self, query):
        return

    async def blockchain_transaction_get(self, query):
        return

    async def blockchain_transaction_get_merkle(self, query):
        return

    async def blockchain_transaction_from_pos(self, query):  # pylint: disable=R0911
        if "params" not in query or len(query["params"]) < 2:
            return {"error": "malformed request"}
        height = query["params"][0]
        tx_pos = query["params"][1]
        merkle = query["params"][2] if len(query["params"]) > 2 else False

        if not is_non_negative_integer(height):
            return {"error": "height is not a non-negative integer"}
        if not is_non_negative_integer(tx_pos):
            return {"error": "tx_pos is not a non-negative integer"}
        if not is_boolean(merkle):
            return {"error": "merkle is not a boolean value"}

        _ec, hashes = await self.bx.fetch_block_transaction_hashes(height)
        if _ec and _ec != 0:
            self.log.debug("Got error: %s", repr(_ec))
            return {"error": "request corrupted"}

        if len(hashes) - 1 < tx_pos:
            return {"error": "index not in block"}

        # Decouple from tuples
        hashes = [i[0] for i in hashes] 
        txid = safe_hexlify(hashes[tx_pos][::-1])

        if not merkle:
            return {"result": txid}
        branch = merkle_branch(hashes, tx_pos)
        return {"result": {"tx_hash": txid, "merkle": branch}}

    async def mempool_get_fee_histogram(self, query):  # pylint: disable=W0613
        # Help wanted
        return {"result": [[0, 0]]}

    async def server_add_peer(self, query):  # pylint: disable=W0613
        # Help wanted
        return {"result": False}

    async def server_banner(self, query):  # pylint: disable=W0613
        return {"result": BANNER}

    async def server_donation_address(self, query):  # pylint: disable=W0613
        return {"result": DONATION_ADDR}

    async def server_features(self, query):
        return

    async def server_peers_subscribe(self, query):  # pylint: disable=W0613
        # Help wanted
        return {"result": []}

    async def server_ping(self, query):  # pylint: disable=W0613
        return {"result": None}

    async def server_version(self, query):
        if self.version_called:
            self.log.warning("Got a subsequent %s call", query["method"])
            return
        if "params" not in query or len(query["params"]) != 2:
            return {"error": "malformed request"}
        client_ver = query["params"][1]
        if isinstance(client_ver, list):
            client_min, client_max = client_ver[0], client_ver[1]
        else:
            client_min = client_max = client_ver
        version = min(client_max, SERVER_PROTO_MAX)
        if version < max(client_min, SERVER_PROTO_MIN):
            return {"error": f"client protocol version {client_ver} is not supported"}
        self.version_called = True
        return {"response": [f"obelisk {VERSION}", version]}
