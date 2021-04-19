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
"""Implementation of the Electrum protocol as found on
https://electrumx-spesmilo.readthedocs.io/en/latest/protocol-methods.html
"""
import asyncio
import json
import struct
from binascii import unhexlify

from obelisk.errors_jsonrpc import JsonRPCError
from obelisk.errors_libbitcoin import ErrorCode
from obelisk.merkle import merkle_branch, merkle_branch_and_root
from obelisk.util import (
    bh2u,
    block_to_header,
    is_boolean,
    is_hash256_str,
    is_hex_str,
    is_non_negative_integer,
    safe_hexlify,
    sha256,
    double_sha256,
    hash_to_hex_str,
)
from obelisk.zeromq import Client

VERSION = "0.0"
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
    """Class implementing the Electrum protocol, with async support"""

    def __init__(self, log, chain, endpoints, server_cfg):
        self.log = log
        self.stopped = False
        self.endpoints = endpoints
        self.server_cfg = server_cfg
        self.loop = asyncio.get_event_loop()
        self.chain_tip = 0
        # Consider renaming bx to something else
        self.bx = Client(log, endpoints, self.loop)
        self.block_queue = None
        # TODO: Clean up on client disconnect
        self.tasks = []
        self.sh_subscriptions = {}

        if chain == "mainnet":  # pragma: no cover
            self.genesis = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        elif chain == "testnet":
            self.genesis = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        else:
            raise ValueError(f"Invalid chain '{chain}'")  # pragma: no cover

        # Here we map available methods to their respective functions
        self.methodmap = {
            "blockchain.block.header": self.block_header,
            "blockchain.block.headers": self.block_headers,
            "blockchain.estimatefee": self.estimatefee,
            "blockchain.headers.subscribe": self.headers_subscribe,
            "blockchain.relayfee": self.relayfee,
            "blockchain.scripthash.get_balance": self.scripthash_get_balance,
            "blockchain.scripthash.get_history": self.scripthash_get_history,
            "blockchain.scripthash.get_mempool": self.scripthash_get_mempool,
            "blockchain.scripthash.listunspent": self.scripthash_listunspent,
            "blockchain.scripthash.subscribe": self.scripthash_subscribe,
            "blockchain.scripthash.unsubscribe": self.scripthash_unsubscribe,
            "blockchain.transaction.broadcast": self.transaction_broadcast,
            "blockchain.transaction.get": self.transaction_get,
            "blockchain.transaction.get_merkle": self.transaction_get_merkle,
            "blockchain.transaction.id_from_pos": self.transaction_id_from_pos,
            "mempool.get_fee_histogram": self.get_fee_histogram,
            "server_add_peer": self.add_peer,
            "server.banner": self.banner,
            "server.donation_address": self.donation_address,
            "server.features": self.server_features,
            "server.peers.subscribe": self.peers_subscribe,
            "server.ping": self.ping,
            "server.version": self.server_version,
        }

    async def stop(self):
        """Destructor function"""
        self.log.debug("ElectrumProtocol.stop()")
        self.stopped = True
        if self.bx:
            unsub_pool = []
            for i in self.sh_subscriptions:  # pragma: no cover
                self.log.debug("bx.unsubscribe %s", i)
                unsub_pool.append(self.bx.unsubscribe_scripthash(i))
            await asyncio.gather(*unsub_pool, return_exceptions=True)
            await self.bx.stop()

        # idxs = []
        # for task in self.tasks:
        # idxs.append(self.tasks.index(task))
        # task.cancel()
        # for i in idxs:
        # del self.tasks[i]

    async def recv(self, reader, writer):
        """Loop ran upon a connection which acts as a JSON-RPC handler"""
        recv_buf = bytearray()
        while not self.stopped:
            data = await reader.read(4096)
            if not data or len(data) == 0:
                self.log.debug("Received EOF, disconnect")
                # TODO: cancel asyncio tasks for this client here?
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
                self.log.debug("=> %s", line)
                await self.handle_query(writer, query)

    async def _send_notification(self, writer, method, params):
        """Send JSON-RPC notification to given writer"""
        response = {"jsonrpc": "2.0", "method": method, "params": params}
        self.log.debug("<= %s", response)
        writer.write(json.dumps(response).encode("utf-8") + b"\n")
        await writer.drain()

    async def _send_response(self, writer, result, nid):
        """Send successful JSON-RPC response to given writer"""
        response = {"jsonrpc": "2.0", "result": result, "id": nid}
        self.log.debug("<= %s", response)
        writer.write(json.dumps(response).encode("utf-8") + b"\n")
        await writer.drain()

    async def _send_error(self, writer, error):
        """Send JSON-RPC error to given writer"""
        response = {"jsonrpc": "2.0", "error": error, "id": None}
        self.log.debug("<= %s", response)
        writer.write(json.dumps(response).encode("utf-8") + b"\n")
        await writer.drain()

    async def _send_reply(self, writer, resp, query):
        """Wrap function for sending replies"""
        if "error" in resp:
            return await self._send_error(writer, resp["error"])
        return await self._send_response(writer, resp["result"], query["id"])

    async def handle_query(self, writer, query):  # pylint: disable=R0915,R0912,R0911
        """Electrum protocol method handler mapper"""
        if "method" not in query:
            self.log.debug("No 'method' in query: %s", query)
            return await self._send_reply(writer, JsonRPCError.invalidrequest(),
                                          None)
        if "id" not in query:
            self.log.debug("No 'id' in query: %s", query)
            return await self._send_reply(writer, JsonRPCError.invalidrequest(),
                                          None)

        method = query["method"]
        func = self.methodmap.get(method)
        if not func:
            self.log.error("Unhandled method %s, query=%s", method, query)
            return await self._send_reply(writer, JsonRPCError.methodnotfound(),
                                          query)
        resp = await func(writer, query)
        return await self._send_reply(writer, resp, query)

    async def _merkle_proof_for_headers(self, height, idx):
        """Extremely inefficient merkle proof for headers"""
        # The following works, but is extremely inefficient.
        # The best solution would be to figure something out in
        # libbitcoin-server
        cp_headers = []

        for i in range(0, height + 1):
            _ec, data = await self.bx.fetch_block_header(i)
            if _ec and _ec != 0:
                self.log.debug("Got error: %s", repr(_ec))
                return JsonRPCError.internalerror()
            cp_headers.append(data)

        branch, root = merkle_branch_and_root(
            [double_sha256(i) for i in cp_headers], idx)

        return {
            "branch": [hash_to_hex_str(i) for i in branch],
            "header": safe_hexlify(cp_headers[idx]),
            "root": hash_to_hex_str(root),
        }

    async def block_header(self, writer, query):  # pylint: disable=W0613,R0911
        """Method: blockchain.block.header
        Return the block header at the given height.
        """
        if "params" not in query or len(query["params"]) < 1:
            return JsonRPCError.invalidparams()
        index = query["params"][0]
        cp_height = query["params"][1] if len(query["params"]) == 2 else 0

        if not is_non_negative_integer(index):
            return JsonRPCError.invalidparams()
        if not is_non_negative_integer(cp_height):
            return JsonRPCError.invalidparams()
        if cp_height != 0 and not index <= cp_height:
            return JsonRPCError.invalidparams()

        if cp_height == 0:
            _ec, header = await self.bx.fetch_block_header(index)
            if _ec and _ec != 0:
                self.log.debug("Got error: %s", repr(_ec))
                return JsonRPCError.internalerror()
            return {"result": safe_hexlify(header)}

        res = await self._merkle_proof_for_headers(cp_height, index)
        return {"result": res}

    async def block_headers(self, writer, query):  # pylint: disable=W0613,R0911
        """Method: blockchain.block.headers
        Return a concatenated chunk of block headers from the main chain.
        """
        if "params" not in query or len(query["params"]) < 2:
            return JsonRPCError.invalidparams()
        # Electrum doesn't allow max_chunk_size to be less than 2016
        # gopher://bitreich.org/9/memecache/convenience-store.mkv
        max_chunk_size = 2016
        start_height = query["params"][0]
        count = query["params"][1]
        cp_height = query["params"][2] if len(query["params"]) == 3 else 0

        if not is_non_negative_integer(start_height):
            return JsonRPCError.invalidparams()
        if not is_non_negative_integer(count):
            return JsonRPCError.invalidparams()
        # BUG: spec says <= cp_height
        if cp_height != 0 and not start_height + (count - 1) < cp_height:
            return JsonRPCError.invalidparams()

        count = min(count, max_chunk_size)
        headers = bytearray()
        for i in range(count):
            _ec, data = await self.bx.fetch_block_header(start_height + i)
            if _ec and _ec != 0:
                self.log.debug("Got error: %s", repr(_ec))
                return JsonRPCError.internalerror()
            headers.extend(data)

        resp = {
            "hex": safe_hexlify(headers),
            "count": len(headers) // 80,
            "max": max_chunk_size,
        }

        if cp_height > 0:
            data = await self._merkle_proof_for_headers(
                cp_height, start_height + (len(headers) // 80) - 1)
            resp["branch"] = data["branch"]
            resp["root"] = data["root"]

        return {"result": resp}

    async def estimatefee(self, writer, query):  # pylint: disable=W0613
        """Method: blockchain.estimatefee
        Return the estimated transaction fee per kilobyte for a transaction
        to be confirmed within a certain number of blocks.
        """
        # TODO: Help wanted
        return {"result": -1}

    async def header_notifier(self, writer):
        self.block_queue = asyncio.Queue()
        await self.bx.subscribe_to_blocks(self.block_queue)
        while True:
            # item = (seq, height, block_data)
            item = await self.block_queue.get()
            if len(item) != 3:
                self.log.debug("error: item from block queue len != 3")
                continue

            self.chain_tip = item[1]
            header = block_to_header(item[2])
            params = [{"height": item[1], "hex": safe_hexlify(header)}]
            await self._send_notification(writer,
                                          "blockchain.headers.subscribe",
                                          params)

    async def headers_subscribe(self, writer, query):  # pylint: disable=W0613
        """Method: blockchain.headers.subscribe
        Subscribe to receive block headers when a new block is found.
        """
        # Tip height and header are returned upon request
        _ec, height = await self.bx.fetch_last_height()
        if _ec and _ec != 0:
            self.log.debug("Got error: %s", repr(_ec))
            return JsonRPCError.internalerror()
        _ec, tip_header = await self.bx.fetch_block_header(height)
        if _ec and _ec != 0:
            self.log.debug("Got error: %s", repr(_ec))
            return JsonRPCError.internalerror()

        self.chain_tip = height
        self.tasks.append(asyncio.create_task(self.header_notifier(writer)))
        ret = {"height": height, "hex": safe_hexlify(tip_header)}
        return {"result": ret}

    async def relayfee(self, writer, query):  # pylint: disable=W0613
        """Method: blockchain.relayfee
        Return the minimum fee a low-priority transaction must pay in order
        to be accepted to the daemon’s memory pool.
        """
        return {"result": 0.00001}

    async def scripthash_get_balance(self, writer, query):  # pylint: disable=W0613
        """Method: blockchain.scripthash.get_balance
        Return the confirmed and unconfirmed balances of a script hash.
        """
        if "params" not in query or len(query["params"]) != 1:
            return JsonRPCError.invalidparams()

        if not is_hash256_str(query["params"][0]):
            return JsonRPCError.invalidparams()

        _ec, data = await self.bx.fetch_balance(query["params"][0])
        if _ec and _ec != 0:
            self.log.debug("Got error: %s", repr(_ec))
            return JsonRPCError.internalerror()

        ret = {"confirmed": data[0], "unconfirmed": data[1]}
        return {"result": ret}

    async def scripthash_get_history(self, writer, query):  # pylint: disable=W0613
        """Method: blockchain.scripthash.get_history
        Return the confirmed and unconfirmed history of a script hash.
        """
        if "params" not in query or len(query["params"]) != 1:
            return JsonRPCError.invalidparams()

        if not is_hash256_str(query["params"][0]):
            return JsonRPCError.invalidparams()

        _ec, data = await self.bx.fetch_history4(query["params"][0])
        if _ec and _ec != 0:
            self.log.debug("Got error: %s", repr(_ec))
            return JsonRPCError.internalerror()

        self.log.debug("hist: %s", data)
        ret = []
        # TODO: mempool
        for i in data:
            if "received" in i:
                ret.append({
                    "height": i["received"]["height"],
                    "tx_hash": hash_to_hex_str(i["received"]["hash"]),
                })
            if "spent" in i:
                ret.append({
                    "height": i["spent"]["height"],
                    "tx_hash": hash_to_hex_str(i["spent"]["hash"]),
                })

        return {"result": ret}

    async def scripthash_get_mempool(self, writer, query):  # pylint: disable=W0613
        """Method: blockchain.scripthash.get_mempool
        Return the unconfirmed transactions of a script hash.
        """
        # TODO: Implement
        return JsonRPCError.invalidrequest()

    async def scripthash_listunspent(self, writer, query):  # pylint: disable=W0613
        """Method: blockchain.scripthash.listunspent
        Return an ordered list of UTXOs sent to a script hash.
        """
        if "params" not in query or len(query["params"]) != 1:
            return JsonRPCError.invalidparams()

        scripthash = query["params"][0]
        if not is_hash256_str(scripthash):
            return JsonRPCError.invalidparams()

        _ec, utxo = await self.bx.fetch_utxo(scripthash)
        if _ec and _ec != 0:
            self.log.debug("Got error: %s", repr(_ec))
            return JsonRPCError.internalerror()

        ret = []
        for i in utxo:
            rec = i["received"]
            ret.append({
                "tx_pos": rec["index"],
                "value": i["value"],
                "tx_hash": hash_to_hex_str(rec["hash"]),
                "height": rec["height"] if rec["height"] != 4294967295 else 0,
            })

        return {"result": ret}

    async def scripthash_notifier(self, writer, scripthash):
        # TODO: Mempool
        method = "blockchain.scripthash.subscribe"
        while True:
            _ec, sh_queue = await self.bx.subscribe_scripthash(scripthash)
            if _ec and _ec != 0:
                self.log.error("bx.subscribe_scripthash failed: %s", repr(_ec))
                return

            item = await sh_queue.get()
            _ec, height, txid = struct.unpack("<HI32s", item)

            if (_ec == ErrorCode.service_stopped.value and height == 0 and
                    not self.stopped):
                # Subscription expired
                continue

            self.sh_subscriptions[scripthash]["status"].append(
                (hash_to_hex_str(txid), height))

            params = [
                scripthash,
                ElectrumProtocol.__scripthash_status_encode(
                    self.sh_subscriptions[scripthash]["status"]),
            ]
            await self._send_notification(writer, method, params)

    async def scripthash_subscribe(self, writer, query):  # pylint: disable=W0613
        """Method: blockchain.scripthash.subscribe
        Subscribe to a script hash.
        """
        if "params" not in query or len(query["params"]) != 1:
            return JsonRPCError.invalidparams()

        scripthash = query["params"][0]
        if not is_hash256_str(scripthash):
            return JsonRPCError.invalidparams()

        _ec, history = await self.bx.fetch_history4(scripthash)
        if _ec and _ec != 0:
            return JsonRPCError.internalerror()

        task = asyncio.create_task(self.scripthash_notifier(writer, scripthash))
        self.sh_subscriptions[scripthash] = {"task": task}

        if len(history) < 1:
            return {"result": None}

        # TODO: Check how history4 acts for mempool/unconfirmed
        status = ElectrumProtocol.__scripthash_status_from_history(history)
        self.sh_subscriptions[scripthash]["status"] = status
        return {"result": ElectrumProtocol.__scripthash_status_encode(status)}

    @staticmethod
    def __scripthash_status_from_history(history):
        status = []
        for i in history:
            if "received" in i:
                status.append((
                    hash_to_hex_str(i["received"]["hash"]),
                    i["received"]["height"],
                ))
            if "spent" in i:
                status.append((
                    hash_to_hex_str(i["spent"]["hash"]),
                    i["spent"]["height"],
                ))
        return status

    @staticmethod
    def __scripthash_status_encode(status):
        concat = ""
        for txid, height in status:
            concat += txid + ":%d:" % height
        return bh2u(sha256(concat.encode("ascii")))

    async def scripthash_unsubscribe(self, writer, query):  # pylint: disable=W0613
        """Method: blockchain.scripthash.unsubscribe
        Unsubscribe from a script hash, preventing future notifications
        if its status changes.
        """
        if "params" not in query or len(query["params"]) != 1:
            return JsonRPCError.invalidparams()

        scripthash = query["params"][0]
        if not is_hash256_str(scripthash):
            return JsonRPCError.invalidparams()

        if scripthash in self.sh_subscriptions:
            self.sh_subscriptions[scripthash]["task"].cancel()
            # await self.bx.unsubscribe_scripthash(scripthash)
            del self.sh_subscriptions[scripthash]
            return {"result": True}

        return {"result": False}

    async def transaction_broadcast(self, writer, query):  # pylint: disable=W0613
        """Method: blockchain.transaction.broadcast
        Broadcast a transaction to the network.
        """
        # Note: Not yet implemented in bs v4
        if "params" not in query or len(query["params"]) != 1:
            return JsonRPCError.invalidparams()

        hextx = query["params"][0]
        if not is_hex_str(hextx):
            return JsonRPCError.invalidparams()

        _ec, _ = await self.bx.broadcast_transaction(unhexlify(hextx)[::-1])
        if _ec and _ec != 0:
            self.log.debug("Got error: %s", repr(_ec))
            return JsonRPCError.internalerror()

        rawtx = unhexlify(hextx)
        txid = double_sha256(rawtx)
        return {"result": hash_to_hex_str(txid)}

    async def transaction_get(self, writer, query):  # pylint: disable=W0613
        """Method: blockchain.transaction.get
        Return a raw transaction.
        """
        if "params" not in query or len(query["params"]) < 1:
            return JsonRPCError.invalidparams()

        tx_hash = query["params"][0]
        verbose = query["params"][1] if len(query["params"]) > 1 else False

        # _ec, rawtx = await self.bx.fetch_blockchain_transaction(tx_hash)
        _ec, rawtx = await self.bx.fetch_mempool_transaction(tx_hash)
        if _ec and _ec != 0 and _ec != ErrorCode.not_found.value:
            self.log.debug("Got error: %s", repr(_ec))
            return JsonRPCError.internalerror()

        # Behaviour is undefined in spec
        if not rawtx:
            return {"result": None}

        if verbose:
            # TODO: Help needed
            return JsonRPCError.invalidrequest()

        return {"result": bh2u(rawtx)}

    async def transaction_get_merkle(self, writer, query):  # pylint: disable=W0613
        """Method: blockchain.transaction.get_merkle
        Return the merkle branch to a confirmed transaction given its
        hash and height.
        """
        if "params" not in query or len(query["params"]) != 2:
            return JsonRPCError.invalidparams()

        tx_hash = query["params"][0]
        height = query["params"][1]

        if not is_hash256_str(tx_hash):
            return JsonRPCError.invalidparams()
        if not is_non_negative_integer(height):
            return JsonRPCError.invalidparams()

        _ec, hashes = await self.bx.fetch_block_transaction_hashes(height)
        if _ec and _ec != 0:
            self.log.debug("Got error: %s", repr(_ec))
            return JsonRPCError.internalerror()

        # Decouple from tuples
        hashes = [i[0] for i in hashes]
        tx_pos = hashes.index(unhexlify(tx_hash)[::-1])
        branch = merkle_branch(hashes, tx_pos)

        res = {
            "block_height": int(height),
            "pos": int(tx_pos),
            "merkle": branch,
        }
        return {"result": res}

    async def transaction_id_from_pos(self, writer, query):  # pylint: disable=R0911,W0613
        """Method: blockchain.transaction.id_from_pos
        Return a transaction hash and optionally a merkle proof, given a
        block height and a position in the block.
        """
        if "params" not in query or len(query["params"]) < 2:
            return JsonRPCError.invalidparams()

        height = query["params"][0]
        tx_pos = query["params"][1]
        merkle = query["params"][2] if len(query["params"]) > 2 else False

        if not is_non_negative_integer(height):
            return JsonRPCError.invalidparams()
        if not is_non_negative_integer(tx_pos):
            return JsonRPCError.invalidparams()
        if not is_boolean(merkle):
            return JsonRPCError.invalidparams()

        _ec, hashes = await self.bx.fetch_block_transaction_hashes(height)
        if _ec and _ec != 0:
            self.log.debug("Got error: %s", repr(_ec))
            return JsonRPCError.internalerror()

        if len(hashes) - 1 < tx_pos:
            return JsonRPCError.internalerror()

        # Decouple from tuples
        hashes = [i[0] for i in hashes]
        txid = hash_to_hex_str(hashes[tx_pos])

        if not merkle:
            return {"result": txid}

        branch = merkle_branch(hashes, tx_pos)
        return {"result": {"tx_hash": txid, "merkle": branch}}

    async def get_fee_histogram(self, writer, query):  # pylint: disable=W0613
        """Method: mempool.get_fee_histogram
        Return a histogram of the fee rates paid by transactions in the
        memory pool, weighted by transaction size.
        """
        # TODO: Help wanted
        return {"result": [[0, 0]]}

    async def add_peer(self, writer, query):  # pylint: disable=W0613
        """Method: server.add_peer
        A newly-started server uses this call to get itself into other
        servers’ peers lists. It should not be used by wallet clients.
        """
        # TODO: Help wanted
        return {"result": False}

    async def banner(self, writer, query):  # pylint: disable=W0613
        """Method: server.banner
        Return a banner to be shown in the Electrum console.
        """
        _, bsversion = await self.bx.server_version()
        banner = "%s\nobelisk version: %s\nlibbitcoin-server version: %s" % (
            BANNER,
            VERSION,
            bsversion.decode(),
        )
        return {"result": banner}

    async def donation_address(self, writer, query):  # pylint: disable=W0613
        """Method: server.donation_address
        Return a server donation address.
        """
        return {"result": DONATION_ADDR}

    async def server_features(self, writer, query):  # pylint: disable=W0613 # pragma: no cover
        """Method: server.features
        Return a list of features and services supported by the server.
        """
        cfg = self.server_cfg
        hosts = {}
        for host in cfg["server_hostnames"]:
            hosts[host] = {"tcp_port": cfg["server_port"]}

        return {
            "result": {
                "genesis_hash": self.genesis,
                "hosts": hosts,
                "protocol_max": SERVER_PROTO_MAX,
                "protocol_min": SERVER_PROTO_MIN,
                "pruning": None,
                "server_version": f"obelisk {VERSION}",
                "hash_function": "sha256",
            }
        }

    async def peers_subscribe(self, writer, query):  # pylint: disable=W0613
        """Method: server.peers.subscribe
        Return a list of peer servers. Despite the name this is not a
        subscription and the server must send no notifications.
        """
        # TODO: Help wanted
        return {"result": []}

    async def ping(self, writer, query):  # pylint: disable=W0613
        """Method: server.ping
        Ping the server to ensure it is responding, and to keep the session
        alive. The server may disconnect clients that have sent no requests
        for roughly 10 minutes.
        """
        return {"result": None}

    async def server_version(self, writer, query):  # pylint: disable=W0613
        """Method: server.version
        Identify the client to the server and negotiate the protocol version.
        """
        if "params" not in query or len(query["params"]) != 2:
            return JsonRPCError.invalidparams()

        client_ver = query["params"][1]

        if isinstance(client_ver, list):
            client_min, client_max = client_ver[0], client_ver[1]
        else:
            client_min = client_max = client_ver

        version = min(client_max, SERVER_PROTO_MAX)

        if version < max(client_min, SERVER_PROTO_MIN):
            return JsonRPCError.protonotsupported()

        return {"result": [f"obelisk {VERSION}", version]}
