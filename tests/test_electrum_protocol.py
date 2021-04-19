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

from obelisk.errors_jsonrpc import JsonRPCError
from obelisk.protocol import (
    ElectrumProtocol,
    VERSION,
    SERVER_PROTO_MIN,
    SERVER_PROTO_MAX,
)
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
        if not data or len(data) == 0:  # pragma: no cover
            raise ValueError("No data received from blockstream")
        recv_buf.extend(data)
        lb = recv_buf.find(b"\n")
        if lb == -1:  # pragma: no cover
            continue
        while lb != -1:
            line = recv_buf[:lb].rstrip()
            recv_buf = recv_buf[lb + 1:]
            lb = recv_buf.find(b"\n")
            line = line.decode("utf-8")
            resp = json.loads(line)
            return resp


def assert_equal(data, expect):  # pragma: no cover
    try:
        assert data == expect
    except AssertionError:
        print("Got:")
        pprint(data)
        print("Expected:")
        pprint(expect)
        raise


async def test_server_version(protocol, writer, method):
    params = ["obelisk 42", [SERVER_PROTO_MIN, SERVER_PROTO_MAX]]
    expect = {"result": [f"obelisk {VERSION}", SERVER_PROTO_MAX]}
    data = await protocol.server_version(writer, {"params": params})
    assert_equal(data["result"], expect["result"])

    params = ["obelisk", "0.0"]
    expect = JsonRPCError.protonotsupported()
    data = await protocol.server_version(writer, {"params": params})
    assert_equal(data, expect)

    params = ["obelisk"]
    expect = JsonRPCError.invalidparams()
    data = await protocol.server_version(writer, {"params": params})
    assert_equal(data, expect)


async def test_ping(protocol, writer, method):
    params = []
    expect = get_expect(method, params)
    data = await protocol.ping(writer, {"params": params})
    assert_equal(data["result"], expect["result"])


async def test_block_header(protocol, writer, method):
    params = [[123], [1, 5]]
    for i in params:
        expect = get_expect(method, i)
        data = await protocol.block_header(writer, {"params": i})
        assert_equal(data["result"], expect["result"])

    params = [[], [-3], [4, -1], [5, 3]]
    for i in params:
        expect = JsonRPCError.invalidparams()
        data = await protocol.block_header(writer, {"params": i})
        assert_equal(data, expect)


async def test_block_headers(protocol, writer, method):
    params = [[123, 3], [11, 3, 14]]
    for i in params:
        expect = get_expect(method, i)
        data = await protocol.block_headers(writer, {"params": i})
        assert_equal(data["result"], expect["result"])

    params = [[], [1], [-3, 1], [4, -1], [7, 4, 4]]
    for i in params:
        expect = JsonRPCError.invalidparams()
        data = await protocol.block_headers(writer, {"params": i})
        assert_equal(data, expect)


async def test_estimatefee(protocol, writer, method):
    params = [2]
    expect = -1
    data = await protocol.estimatefee(writer, {"params": params})
    assert_equal(data["result"], expect)


async def test_headers_subscribe(protocol, writer, method):
    params = [[]]
    for i in params:
        expect = get_expect(method, i)
        data = await protocol.headers_subscribe(writer, {"params": i})
        assert_equal(data["result"], expect["result"])


async def test_relayfee(protocol, writer, method):
    expect = 0.00001
    data = await protocol.relayfee(writer, {"params": []})
    assert_equal(data["result"], expect)


async def test_scripthash_get_balance(protocol, writer, method):
    params = [
        ["c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921"],
        ["92dd1eb7c042956d3dd9185a58a2578f61fee91347196604540838ccd0f8c08c"],
        ["b97b504af8fcf94a47d3ae5a346d38220f0751732d9b89a413568bfbf4b36ec6"],
    ]
    for i in params:
        expect = get_expect(method, i)
        data = await protocol.scripthash_get_balance(writer, {"params": i})
        assert_equal(data["result"], expect["result"])

    params = [
        [],
        ["foobar"],
        [
            "c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921",
            42,
        ],
    ]
    for i in params:
        expect = JsonRPCError.invalidparams()
        data = await protocol.scripthash_get_balance(writer, {"params": i})
        assert_equal(data, expect)


async def test_scripthash_get_history(protocol, writer, method):
    params = [
        ["c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921"],
        ["b97b504af8fcf94a47d3ae5a346d38220f0751732d9b89a413568bfbf4b36ec6"],
    ]
    for i in params:
        expect = get_expect(method, i)
        data = await protocol.scripthash_get_history(writer, {"params": i})
        assert_equal(data["result"], expect["result"])

    params = [
        [],
        ["foobar"],
        [
            "c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921",
            42,
        ],
    ]
    for i in params:
        expect = JsonRPCError.invalidparams()
        data = await protocol.scripthash_get_history(writer, {"params": i})
        assert_equal(data, expect)


async def test_scripthash_listunspent(protocol, writer, method):
    params = [
        ["c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921"],
        ["92dd1eb7c042956d3dd9185a58a2578f61fee91347196604540838ccd0f8c08c"],
        ["b97b504af8fcf94a47d3ae5a346d38220f0751732d9b89a413568bfbf4b36ec6"],
    ]
    for i in params:
        # Blockstream is broken here and doesn't return in ascending order.
        expect = get_expect(method, i)
        srt = sorted(expect["result"], key=lambda x: x["height"])
        data = await protocol.scripthash_listunspent(writer, {"params": i})
        assert_equal(data["result"], srt)

    params = [
        [],
        ["foobar"],
        [
            "c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921",
            42,
        ],
    ]
    for i in params:
        expect = JsonRPCError.invalidparams()
        data = await protocol.scripthash_listunspent(writer, {"params": i})
        assert_equal(data, expect)


async def test_scripthash_subscribe(protocol, writer, method):
    params = [
        ["92dd1eb7c042956d3dd9185a58a2578f61fee91347196604540838ccd0f8c08c"],
    ]
    for i in params:
        expect = get_expect(method, i)
        data = await protocol.scripthash_subscribe(writer, {"params": i})
        assert_equal(data["result"], expect["result"])

    params = [
        [],
        ["foobar"],
        [
            "c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921",
            42,
        ],
    ]
    for i in params:
        expect = JsonRPCError.invalidparams()
        data = await protocol.scripthash_subscribe(writer, {"params": i})
        assert_equal(data, expect)


async def test_scripthash_unsubscribe(protocol, writer, method):
    # Here blockstream doesn't even care
    params = [
        ["92dd1eb7c042956d3dd9185a58a2578f61fee91347196604540838ccd0f8c08c"],
    ]
    for i in params:
        data = await protocol.scripthash_unsubscribe(writer, {"params": i})
        assert data["result"] is True

    params = [
        [],
        ["foobar"],
        [
            "c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921",
            42,
        ],
    ]
    for i in params:
        expect = JsonRPCError.invalidparams()
        data = await protocol.scripthash_unsubscribe(writer, {"params": i})
        assert_equal(data, expect)


async def test_transaction_get(protocol, writer, method):
    params = [
        ["a9c3c22cc2589284288b28e802ea81723d649210d59dfa7e03af00475f4cec20"],
    ]
    for i in params:
        expect = get_expect(method, i)
        data = await protocol.transaction_get(writer, {"params": i})
        assert_equal(data["result"], expect["result"])

    params = [[], [1], ["foo"], ["dead beef"]]
    for i in params:
        expect = JsonRPCError.invalidparams()
        data = await protocol.transaction_get(writer, {"params": i})
        assert_equal(data, expect)


async def test_transaction_get_merkle(protocol, writer, method):
    params = [
        [
            "a9c3c22cc2589284288b28e802ea81723d649210d59dfa7e03af00475f4cec20",
            1970700,
        ],
    ]
    for i in params:
        expect = get_expect(method, i)
        data = await protocol.transaction_get_merkle(writer, {"params": i})
        assert_equal(data["result"], expect["result"])

    params = [
        [],
        ["foo", 1],
        [3, 1],
        [
            "a9c3c22cc2589284288b28e802ea81723d649210d59dfa7e03af00475f4cec20",
            -4,
        ],
        [
            "a9c3c22cc2589284288b28e802ea81723d649210d59dfa7e03af00475f4cec20",
            "foo",
        ],
    ]
    for i in params:
        expect = JsonRPCError.invalidparams()
        data = await protocol.transaction_get_merkle(writer, {"params": i})
        assert_equal(data, expect)


async def test_transaction_id_from_pos(protocol, writer, method):
    params = [[1970700, 28], [1970700, 28, True]]
    for i in params:
        expect = get_expect(method, i)
        data = await protocol.transaction_id_from_pos(writer, {"params": i})
        assert_equal(data["result"], expect["result"])

    params = [[123], [-1, 1], [1, -1], [3, 42, 4]]
    for i in params:
        expect = JsonRPCError.invalidparams()
        data = await protocol.transaction_id_from_pos(writer, {"params": i})
        assert_equal(data, expect)


async def test_get_fee_histogram(protocol, writer, method):
    data = await protocol.get_fee_histogram(writer, {"params": []})
    assert_equal(data["result"], [[0, 0]])


async def test_add_peer(protocol, writer, method):
    data = await protocol.add_peer(writer, {"params": []})
    assert_equal(data["result"], False)


async def test_banner(protocol, writer, method):
    data = await protocol.banner(writer, {"params": []})
    assert_equal(type(data["result"]), str)


async def test_donation_address(protocol, writer, method):
    data = await protocol.donation_address(writer, {"params": []})
    assert_equal(type(data["result"]), str)


async def test_peers_subscribe(protocol, writer, method):
    data = await protocol.peers_subscribe(writer, {"params": []})
    assert_equal(data["result"], [])


async def test_send_notification(protocol, writer, method):
    params = ["sent notification"]
    expect = (json.dumps({
        "jsonrpc": "2.0",
        "method": method,
        "params": params
    }).encode("utf-8") + b"\n")
    await protocol._send_notification(writer, method, params)
    assert_equal(writer.mock, expect)


async def test_send_reply(protocol, writer, method):
    error = {"error": {"code": 42, "message": 42}}
    result = {"result": 42}

    expect = (json.dumps({
        "jsonrpc": "2.0",
        "error": error["error"],
        "id": None
    }).encode("utf-8") + b"\n")
    await protocol._send_reply(writer, error, None)
    assert_equal(writer.mock, expect)

    expect = (json.dumps({
        "jsonrpc": "2.0",
        "result": result["result"],
        "id": 42
    }).encode("utf-8") + b"\n")
    await protocol._send_reply(writer, result, {"id": 42})
    assert_equal(writer.mock, expect)


async def test_handle_query(protocol, writer, method):
    query = {"jsonrpc": "2.0", "method": method, "id": 42, "params": []}
    await protocol.handle_query(writer, query)

    method = "server.donation_address"
    query = {"jsonrpc": "2.0", "method": method, "id": 42, "params": []}
    await protocol.handle_query(writer, query)

    query = {"jsonrpc": "2.0", "method": method, "params": []}
    await protocol.handle_query(writer, query)

    query = {"jsonrpc": "2.0", "id": 42, "params": []}
    await protocol.handle_query(writer, query)


class MockTransport:

    def __init__(self):
        self.peername = ("foo", 42)

    def get_extra_info(self, param):
        return self.peername


class MockWriter(asyncio.StreamWriter):  # pragma: no cover
    """Mock class for StreamWriter"""

    def __init__(self):
        self.mock = None
        self._transport = MockTransport()

    def write(self, data):
        self.mock = data
        return True

    async def drain(self):
        return True


# Test orchestration
orchestration = {
    "server.version": test_server_version,
    "server.ping": test_ping,
    "blockchain.block.header": test_block_header,
    "blockchain.block.headers": test_block_headers,
    "blockchain.estimatefee": test_estimatefee,
    "blockchain.headers.subscribe": test_headers_subscribe,
    "blockchain.relayfee": test_relayfee,
    "blockchain.scripthash.get_balance": test_scripthash_get_balance,
    "blockchain.scripthash.get_history": test_scripthash_get_history,
    # "blockchain.scripthash.get_mempool": test_scripthash_get_mempool,
    "blockchain.scripthash.listunspent": test_scripthash_listunspent,
    "blockchain.scripthash.subscribe": test_scripthash_subscribe,
    "blockchain.scripthash.unsubscribe": test_scripthash_unsubscribe,
    # "blockchain.transaction.broadcast": test_transaction_broadcast,
    "blockchain.transaction.get": test_transaction_get,
    "blockchain.transaction.get_merkle": test_transaction_get_merkle,
    "blockchain.transaction.id_from_pos": test_transaction_id_from_pos,
    "mempool.get_fee_histogram": test_get_fee_histogram,
    "server.add_peer": test_add_peer,
    "server.banner": test_banner,
    "server.donation_address": test_donation_address,
    # "server.features": test_server_features,
    "server.peers_subscribe": test_peers_subscribe,
    "_send_notification": test_send_notification,
    "_send_reply": test_send_reply,
    "_handle_query": test_handle_query,
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

    protocol.peers[protocol._get_peer(writer)] = {"tasks": [], "sh": {}}

    for func in orchestration:
        try:
            await orchestration[func](protocol, writer, func)
            print(f"PASS: {func}")
            test_pass.append(func)
        except AssertionError:  # pragma: no cover
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
