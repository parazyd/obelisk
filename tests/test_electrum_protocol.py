#!/usr/bin/env python3
# Copyright (C) 2021 Ivan J. <parazyd@dyne.org>
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
"""
Test unit for the Electrum protocol. Takes results from testnet
blockstream.info:143 server as value reference.

See bottom of file for test orchestration.
"""
import asyncio
import json
import sys
import traceback
from logging import getLogger
from pprint import pprint
from socket import socket, AF_INET, SOCK_STREAM

from obelisk.protocol import ElectrumProtocol
from obelisk.zeromq import create_random_id

libbitcoin = {
    "query": "tcp://testnet2.libbitcoin.net:29091",
    "heart": "tcp://testnet2.libbitcoin.net:29092",
    "block": "tcp://testnet2.libbitcoin.net:29093",
    "trans": "tcp://testnet2.libbitcoin.net:29094",
}

blockstream = ("blockstream.info", 143)
bs = None  # Socket


def get_expect(method, params):
    global bs
    req = {
        "json-rpc": "2.0",
        "id": create_random_id(),
        "method": method,
        "params": params,
    }
    bs.send(json.dumps(req).encode("utf-8") + b"\n")
    recv_buf = bytearray()
    while True:
        data = bs.recv(4096)
        if not data or len(data) == 0:
            raise ValueError("No data received from blockstream")
        recv_buf.extend(data)
        lb = recv_buf.find(b"\n")
        if lb == -1:
            continue
        while lb != -1:
            line = recv_buf[:lb].rstrip()
            recv_buf = recv_buf[lb + 1:]
            lb = recv_buf.find(b"\n")
            line = line.decode("utf-8")
            resp = json.loads(line)
            return resp


async def test_blockchain_block_header(protocol, writer):
    method = "blockchain.block.header"
    params = [123]
    expect = get_expect(method, params)
    data = await protocol.blockchain_block_header(writer, {"params": params})
    assert data["result"] == expect["result"]

    params = [1, 5]
    expect = get_expect(method, params)
    data = await protocol.blockchain_block_header(writer, {"params": params})
    assert data["result"] == expect["result"]


async def test_blockchain_block_headers(protocol, writer):
    method = "blockchain.block.headers"
    params = [123, 3]
    expect = get_expect(method, params)
    data = await protocol.blockchain_block_headers(writer, {"params": params})
    assert data["result"] == expect["result"]

    # params = [1, 4, 11]
    params = [11, 3, 14]
    expect = get_expect(method, params)
    data = await protocol.blockchain_block_headers(writer, {"params": params})
    assert data["result"] == expect["result"]


async def test_blockchain_scripthash_get_balance(protocol, writer):
    method = "blockchain.scripthash.get_balance"
    params = [
        "c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921"
    ]
    expect = get_expect(method, params)
    data = await protocol.blockchain_scripthash_get_balance(
        writer, {"params": params})
    assert data["result"] == expect["result"]

    params = [
        "92dd1eb7c042956d3dd9185a58a2578f61fee91347196604540838ccd0f8c08c"
    ]
    expect = get_expect(method, params)
    data = await protocol.blockchain_scripthash_get_balance(
        writer, {"params": params})
    assert data["result"] == expect["result"]


async def test_blockchain_scripthash_get_history(protocol, writer):
    method = "blockchain.scripthash.get_history"
    params = [
        "c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921"
    ]
    expect = get_expect(method, params)
    data = await protocol.blockchain_scripthash_get_history(
        writer, {"params": params})
    assert data["result"] == expect["result"]


async def test_blockchain_scripthash_listunspent(protocol, writer):
    method = "blockchain.scripthash.listunspent"
    params = [
        "c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921"
    ]
    expect = get_expect(method, params)
    data = await protocol.blockchain_scripthash_listunspent(
        writer, {"params": params})
    assert data["result"] == expect["result"]

    params = [
        "92dd1eb7c042956d3dd9185a58a2578f61fee91347196604540838ccd0f8c08c"
    ]
    # Blockstream is broken here and doesn't return in ascending order.
    expect = get_expect(method, params)
    srt = sorted(expect["result"], key=lambda x: x["height"])
    data = await protocol.blockchain_scripthash_listunspent(
        writer, {"params": params})
    assert data["result"] == srt


async def test_blockchain_scripthash_subscribe(protocol, writer):
    method = "blockchain.scripthash.subscribe"
    params = [
        "92dd1eb7c042956d3dd9185a58a2578f61fee91347196604540838ccd0f8c08c"
    ]
    expect = get_expect(method, params)
    data = await protocol.blockchain_scripthash_subscribe(
        writer, {"params": params})
    assert data["result"] == expect["result"]


async def test_blockchain_scripthash_unsubscribe(protocol, writer):
    # Here blockstream doesn't even care
    params = [
        "92dd1eb7c042956d3dd9185a58a2578f61fee91347196604540838ccd0f8c08c"
    ]
    data = await protocol.blockchain_scripthash_unsubscribe(
        writer, {"params": params})
    assert data["result"] is True


async def test_blockchain_transaction_get(protocol, writer):
    method = "blockchain.transaction.get"
    params = [
        "a9c3c22cc2589284288b28e802ea81723d649210d59dfa7e03af00475f4cec20"
    ]
    expect = get_expect(method, params)
    data = await protocol.blockchain_transaction_get(writer, {"params": params})
    assert data["result"] == expect["result"]


async def test_blockchain_transaction_get_merkle(protocol, writer):
    method = "blockchain.transaction.get_merkle"
    params = [
        "a9c3c22cc2589284288b28e802ea81723d649210d59dfa7e03af00475f4cec20",
        1970700,
    ]
    expect = get_expect(method, params)
    data = await protocol.blockchain_transaction_get_merkle(
        writer, {"params": params})
    assert data["result"] == expect["result"]


async def test_blockchain_transaction_id_from_pos(protocol, writer):
    method = "blockchain.transaction.id_from_pos"
    params = [1970700, 28]
    expect = get_expect(method, params)
    data = await protocol.blockchain_transaction_id_from_pos(
        writer, {"params": params})
    assert data["result"] == expect["result"]

    params = [1970700, 28, True]
    expect = get_expect(method, params)
    data = await protocol.blockchain_transaction_id_from_pos(
        writer, {"params": params})
    assert data["result"] == expect["result"]


async def test_server_ping(protocol, writer):
    method = "server.ping"
    params = []
    expect = get_expect(method, params)
    data = await protocol.server_ping(writer, {"params": params})
    assert data["result"] == expect["result"]


class MockWriter(asyncio.StreamWriter):
    """Mock class for StreamWriter"""

    def __init__(self):
        self.mock = None

    def write(self, data):
        return True

    async def drain(self):
        return True


# Test orchestration
orchestration = {
    "blockchain_block_header":
        test_blockchain_block_header,
    "blockchain_block_headers":
        test_blockchain_block_headers,
    # "blockchain_estimatefee": test_blockchain_estimatefee,
    # "blockchain_headers_subscribe": test_blockchain_headers_subscribe,
    # "blockchain_relayfee": test_blockchain_relayfee,
    "blockchain_scripthash_get_balance":
        test_blockchain_scripthash_get_balance,
    "blockchain_scripthash_get_history":
        test_blockchain_scripthash_get_history,
    # "blockchain_scripthash_get_mempool": test_blockchain_scripthash_get_mempool,
    "blockchain_scripthash_listunspent":
        test_blockchain_scripthash_listunspent,
    "blockchain_scripthash_subscribe":
        test_blockchain_scripthash_subscribe,
    "blockchain_scripthash_unsubscribe":
        test_blockchain_scripthash_unsubscribe,
    # "blockchain_transaction_broadcast": test_blockchain_transaction_broadcast,
    "blockchain_transaction_get":
        test_blockchain_transaction_get,
    "blockchain_transaction_get_merkle":
        test_blockchain_transaction_get_merkle,
    "blockchain_transaction_id_from_pos":
        test_blockchain_transaction_id_from_pos,
    # "mempool_get_fee_histogram": test_mempool_get_fee_histogram,
    # "server_add_peer": test_server_add_peer,
    # "server_donation_address": test_server_donation_address,
    # "server_features": test_server_features,
    # "server_peers_subscribe": test_server_peers_subscribe,
    "server_ping":
        test_server_ping,
    # "server_version": test_server_version,
}


async def main():
    test_pass = []
    test_fail = []

    global bs
    bs = socket(AF_INET, SOCK_STREAM)
    bs.connect(blockstream)

    log = getLogger("obelisktest")
    protocol = ElectrumProtocol(log, "testnet", libbitcoin, {})
    writer = MockWriter()

    for func in orchestration:
        try:
            await orchestration[func](protocol, writer)
            print(f"PASS: {func}")
            test_pass.append(func)
        except AssertionError:
            print(f"FAIL: {func}")
            traceback.print_exc()
            test_fail.append(func)

    bs.close()
    await protocol.stop()

    print()
    print(f"Tests passed: {len(test_pass)}")
    print(f"Tests failed: {len(test_fail)}")

    ret = 1 if len(test_fail) > 0 else 0
    sys.exit(ret)


if __name__ == "__main__":
    asyncio.run(main())
