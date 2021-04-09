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
import asyncio
import sys
from logging import getLogger

from electrumobelisk.protocol import ElectrumProtocol

#
# See bottom of this file for test orchestration.
#

ENDPOINTS = {
    "query": "tcp://testnet2.libbitcoin.net:29091",
    "heart": "tcp://testnet2.libbitcoin.net:29092",
    "block": "tcp://testnet2.libbitcoin.net:29093",
    "trans": "tcp://testnet2.libbitcoin.net:29094",
}


async def test_blockchain_block_header(protocol, writer):
    expect = "01000000c54675276e0401706aa93db6494dd7d1058b19424f23c8d7c01076da000000001c4375c8056b0ded0fa3d7fc1b5511eaf53216aed72ea95e1b5d19eccbe855f91a184a4dffff001d0336a226"
    query = {"params": [123]}
    res = await protocol.blockchain_block_header(writer, query)
    if "error" in res and "result" not in res:
        return "blockchain_block_header", False
    if res["result"] != expect:
        return "blockchain_block_header", False
    return "blockchain_block_header", True


async def test_blockchain_block_headers(protocol, writer):
    expect = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180100000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000bac8b0fa927c0ac8234287e33c5f74d38d354820e24756ad709d7038fc5f31f020e7494dffff001d03e4b6720100000006128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000e241352e3bec0a95a6217e10c3abb54adfa05abb12c126695595580fb92e222032e7494dffff001d00d23534"
    query = {"params": [123, 3]}
    res = await protocol.blockchain_block_headers(writer, query)
    if "error" in res and "result" not in res:
        return "blockchain_block_headers", False
    if res["result"]["hex"] != expect:
        return "blockchain_block_headers", False
    return "blockchain_block_headers", True


async def test_blockchain_estimatefee(protocol, writer):
    expect = -1
    query = {"params": []}
    res = await protocol.blockchain_estimatefee(writer, query)
    if "error" in res and "result" not in res:
        return "blockchain_estimatefee", False
    if res["result"] != expect:
        return "blockchain_estimatefee", False
    return "blockchain_estimatefee", True


async def test_blockchain_relayfee(protocol, writer):
    expect = 0.00001
    query = {"params": []}
    res = await protocol.blockchain_relayfee(writer, query)
    if "error" in res and "result" not in res:
        return "blockchain_relayfee", False
    if res["result"] != expect:
        return "blockchain_relayfee", False
    return "blockchain_relayfee", True


async def test_blockchain_scripthash_get_balance(protocol, writer):
    shs = [
        "c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921",
        "92dd1eb7c042956d3dd9185a58a2578f61fee91347196604540838ccd0f8c08c",
    ]
    expect = [
        {
            "result": {
                "confirmed": 0,
                "unconfirmed": 0
            }
        },
        {
            "result": {
                "confirmed": 831000,
                "unconfirmed": 0
            }
        },
    ]

    res = []
    for i in shs:
        params = {"params": [i]}
        res.append(await
                   protocol.blockchain_scripthash_get_balance(writer, params))

    for i in expect:
        if res[expect.index(i)] != i:
            return "blockchain_scripthash_get_balance", False
    return "blockchain_scripthash_get_balance", True


async def test_blockchain_scripthash_get_history(protocol, writer):
    shs = [
        "c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921",
        "92dd1eb7c042956d3dd9185a58a2578f61fee91347196604540838ccd0f8c08c",
    ]
    expect = [
        (
            1936167,
            "084eba0e08c78b63e07535b74a5a849994d49afade95d0d205e4963e3f568600",
        ),
        (
            1936171,
            "705c4f265df23726c09c5acb80f9e8a85845c17d68974d89814383855c8545a2",
        ),
        (
            1936171,
            "705c4f265df23726c09c5acb80f9e8a85845c17d68974d89814383855c8545a2",
        ),
        (
            1970700,
            "a9c3c22cc2589284288b28e802ea81723d649210d59dfa7e03af00475f4cec20",
        ),
    ]

    res = []
    for i in shs:
        params = {"params": [i]}
        data = await protocol.blockchain_scripthash_get_history(writer, params)
        if "result" in data:
            for j in data["result"]:
                res.append((j["height"], j["tx_hash"]))

    if expect != res:
        return "blockchain_scripthash_get_history", False
    return "blockchain_scripthash_get_history", True


async def test_blockchain_scripthash_listunspent(protocol, writer):
    shs = [
        "c036b0ff3ad79662cd517cd5fe1fa0af07377b9262d16f276f11ced69aaa6921",
        "92dd1eb7c042956d3dd9185a58a2578f61fee91347196604540838ccd0f8c08c",
    ]

    expect = [
        [],
        [1, 731000, 1936171],
        [1, 100000, 1970700],
    ]

    res = []
    for i in shs:
        params = {"params": [i]}
        data = await protocol.blockchain_scripthash_listunspent(writer, params)
        if "result" in data and len(data["result"]) > 0:
            for j in data["result"]:
                res.append([j["tx_pos"], j["value"], j["height"]])
        else:
            res.append([])

    if res != expect:
        return "blockchain_scripthash_listunspent", False
    return "blockchain_scripthash_listunspent", True


async def test_blockchain_transaction_get(protocol, writer):
    expect = "020000000001011caa5f4ba91ff0ab77712851c1b17943e68f28d46bb0d96cbc13cdbef53c2b87000000001716001412e6e94028ab399b67c1232383d12f1dd3fc03b5feffffff02a40111000000000017a914ff1d7f4c85c562764ca16daa11e97d10eda52ebf87a0860100000000001976a9144a0360eac874a569e82ca6b17274d90bccbcab5e88ac0247304402205392417f5ffba2c0f3a501476fb6872368b2065c53bf18b2a201691fb88cdbe5022016c68ec9e094ba2b06d4bdc6af996ac74b580ab9728c622bb5304aaff04cb6980121031092742ffdf5901ceafcccec090c58170ce1d0ec26963ef7c7a2738a415a317e0b121e00"
    params = {
        "params":
        ["a9c3c22cc2589284288b28e802ea81723d649210d59dfa7e03af00475f4cec20"]
    }
    data = await protocol.blockchain_transaction_get(writer, params)

    if "result" not in data and data["result"] != expect:
        return "blockchain_transaction_get", False
    return "blockchain_transaction_get", True


class MockWriter(asyncio.StreamWriter):
    """Mock class for StreamWriter"""
    def __init__(self):
        self.mock = None

    def write(self, data):
        return True

    async def drain(self):
        return True


async def main():
    test_pass = []
    test_fail = []

    log = getLogger("obelisktest")
    protocol = ElectrumProtocol(log, "testnet", ENDPOINTS, {})
    writer = MockWriter()
    functions = [
        test_blockchain_block_header,
        test_blockchain_block_headers,
        test_blockchain_estimatefee,
        # test_blockchain_headers_subscribe,
        test_blockchain_relayfee,
        test_blockchain_scripthash_get_balance,
        test_blockchain_scripthash_get_history,
        # test_blockchain_scripthash_get_mempool,
        test_blockchain_scripthash_listunspent,
        # test_blockchain_scripthash_subscribe,
        # test_blockchain_scripthash_unsubscribe,
        # test_blockchain_transaction_broadcast,
        test_blockchain_transaction_get,
        # test_blockchain_transaction_get_merkle,
        # test_blockchain_transaction_from_pos,
        # test_mempool_get_fee_histogram,
        # test_server_add_peer,
        # test_server_banner,
        # test_server_donation_address,
        # test_server_features,
        # test_server_peers_subscribe,
        # test_server_ping,
        # test_server_version,
    ]

    for func in functions:
        name, result = await func(protocol, writer)
        if result:
            test_pass.append(name)
            print(f"PASS: {name}")
        else:
            print(f"FAIL: {name}")
            test_fail.append(name)

    await protocol.stop()

    print()
    print(f"Tests passed: {len(test_pass)}")
    print(f"Tests failed: {len(test_fail)}")

    ret = 1 if len(test_fail) > 0 else 0
    sys.exit(ret)


if __name__ == "__main__":
    asyncio.run(main())
