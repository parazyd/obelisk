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
"""ZeroMQ implementation for libbitcoin"""
import asyncio
import functools
import struct
from binascii import unhexlify
from random import randint

import zmq
import zmq.asyncio

from obelisk.errors_libbitcoin import make_error_code, ErrorCode
from obelisk.util import hash_to_hex_str


def create_random_id():
    """Generate a random request ID"""
    max_uint32 = 4294967295
    return randint(0, max_uint32)


def pack_block_index(index):
    """struct.pack given index"""
    if isinstance(index, str):
        index = unhexlify(index)
        assert len(index) == 32
        return index
    if isinstance(index, int):
        return struct.pack("<I", index)

    raise ValueError(
        f"Unknown index type {type(index)} v:{index}, should be int or bytearray"
    )


def to_int(xbytes):
    """Make little-endian integer from given bytes"""
    return int.from_bytes(xbytes, byteorder="little")


def checksum(xhash, index):
    """
    This method takes a transaction hash and an index and returns a checksum.

    This checksum is based on 49 bits starting from the 12th byte of the
    reversed hash. Combined with the last 15 bits of the 4 byte index.
    """
    mask = 0xFFFFFFFFFFFF8000
    magic_start_position = 12

    hash_bytes = bytes.fromhex(xhash)[::-1]
    last_20_bytes = hash_bytes[magic_start_position:]

    assert len(hash_bytes) == 32
    assert index < 2**32

    hash_upper_49_bits = to_int(last_20_bytes) & mask
    index_lower_15_bits = index & ~mask
    return hash_upper_49_bits | index_lower_15_bits


def unpack_table(row_fmt, data):
    """Function to unpack table received from libbitcoin"""
    # Get the number of rows
    row_size = struct.calcsize(row_fmt)
    nrows = len(data) // row_size
    # Unpack
    rows = []
    for idx in range(nrows):
        offset = idx * row_size
        row = struct.unpack_from(row_fmt, data, offset)
        rows.append(row)
    return rows


class ClientSettings:
    """Class implementing ZMQ client settings"""

    def __init__(self, timeout=10, context=None, loop=None):
        self._timeout = timeout
        self._context = context
        self._loop = loop

    @property
    def context(self):
        """ZMQ context property"""
        if not self._context:
            ctx = zmq.asyncio.Context()
            ctx.linger = 500  # in milliseconds
            self._context = ctx
        return self._context

    @context.setter
    def context(self, context):
        self._context = context

    @property
    def timeout(self):
        """Set to None for no timeout"""
        return self._timeout

    @timeout.setter
    def timeout(self, timeout):
        self._timeout = timeout


class Request:
    """Class implementing a _send_ request.
    This is either a simple request/response affair or a subscription.
    """

    def __init__(self, socket, command, data):
        self.id_ = create_random_id()
        self.socket = socket
        self.command = command
        self.data = data
        self.future = asyncio.Future()
        self.queue = None

    async def send(self):
        """Send the ZMQ request"""
        request = [self.command, struct.pack("<I", self.id_), self.data]
        await self.socket.send_multipart(request)

    def is_subscription(self):
        """If the request is a subscription, then the response to this
        request is a notification.
        """
        return self.queue is not None

    def __str__(self):
        return "Request(command, ID) {}, {:d}".format(self.command, self.id_)


class InvalidServerResponseException(Exception):
    """Exception for invalid server responses"""


class Response:
    """Class implementing a request response"""

    def __init__(self, frame):
        if len(frame) != 3:
            raise InvalidServerResponseException(
                f"Length of the frame was not 3: {len(frame)}")

        self.command = frame[0]
        self.request_id = struct.unpack("<I", frame[1])[0]
        error_code = struct.unpack("<I", frame[2][:4])[0]
        self.error_code = make_error_code(error_code)
        self.data = frame[2][4:]

    def is_bound_for_queue(self):
        return len(self.data) > 0

    def __str__(self):
        return (
            "Response(command, request ID, error code, data):" +
            f" {self.command}, {self.request_id}, {self.error_code}, {self.data}"
        )


class RequestCollection:
    """RequestCollection carries a list of Requests and matches incoming
    responses to them.
    """

    def __init__(self, socket, loop):
        self._socket = socket
        self._requests = {}
        self._task = asyncio.ensure_future(self._run(), loop=loop)

    async def _run(self):
        while True:
            await self._receive()

    async def stop(self):
        """Stops listening for incoming responses (or subscription) messages.
        Returns the number of _responses_ expected but which are now dropped
        on the floor.
        """
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            return len(self._requests)

    async def _receive(self):
        frame = await self._socket.recv_multipart()
        response = Response(frame)

        if response.request_id in self._requests:
            self._handle_response(response)
        else:
            print(
                f"DEBUG: RequestCollection unhandled response {response.command}:{response.request_id}"  # pylint: disable=C0301
            )

    def _handle_response(self, response):
        request = self._requests[response.request_id]

        if request.is_subscription():
            if response.is_bound_for_queue():
                # TODO: decode the data into something usable
                request.queue.put_nowait(response.data)
            else:
                request.future.set_result(response)
        else:
            self.delete_request(request)
            request.future.set_result(response)

    def add_request(self, request):
        # TODO: we should maybe check if the request.id_ is unique
        self._requests[request.id_] = request

    def delete_request(self, request):
        del self._requests[request.id_]


class Client:
    """This class represents a connection to a libbitcoin server."""

    def __init__(self, log, endpoints, loop):
        self.log = log
        self._endpoints = endpoints
        self._settings = ClientSettings(loop=loop)
        self._query_socket = self._create_query_socket()
        self._block_socket = self._create_block_socket()
        self._request_collection = RequestCollection(self._query_socket,
                                                     self._settings._loop)

    async def stop(self):
        self.log.debug("zmq Client.stop()")
        self._query_socket.close()
        self._block_socket.close()
        return await self._request_collection.stop()

    def _create_block_socket(self):
        socket = self._settings.context.socket(
            zmq.SUB,  # pylint: disable=E1101
            io_loop=self._settings._loop,  # pylint: disable=W0212
        )
        socket.connect(self._endpoints["block"])
        socket.setsockopt_string(zmq.SUBSCRIBE, "")  # pylint: disable=E1101
        return socket

    def _create_query_socket(self):
        socket = self._settings.context.socket(
            zmq.DEALER,  # pylint: disable=E1101
            io_loop=self._settings._loop,  # pylint: disable=W0212
        )
        socket.connect(self._endpoints["query"])
        return socket

    async def _subscription_request(self, command, data):
        request = await self._request(command, data)
        request.queue = asyncio.Queue(loop=self._settings._loop)  # pylint: disable=W0212
        error_code, _ = await self._wait_for_response(request)
        return error_code, request.queue

    async def _simple_request(self, command, data):
        return await self._wait_for_response(await self._request(command, data))

    async def _request(self, command, data):
        """Make a generic request. Both options are byte objects specified
        like b'blockchain.fetch_block_header' as an example.
        """
        request = Request(self._query_socket, command, data)
        await request.send()
        self._request_collection.add_request(request)
        return request

    async def _wait_for_response(self, request):
        try:
            response = await asyncio.wait_for(request.future,
                                              self._settings.timeout)
        except asyncio.TimeoutError:
            self._request_collection.delete_request(request)
            return ErrorCode.channel_timeout, None

        assert response.command == request.command
        assert response.request_id == request.id_
        return response.error_code, response.data

    async def fetch_last_height(self):
        """Fetch the blockchain tip and return integer height"""
        command = b"blockchain.fetch_last_height"
        error_code, data = await self._simple_request(command, b"")
        if error_code:
            return error_code, None
        return error_code, struct.unpack("<I", data)[0]

    async def fetch_block_header(self, index):
        """Fetch a block header by its height or integer index"""
        command = b"blockchain.fetch_block_header"
        data = pack_block_index(index)
        return await self._simple_request(command, data)

    async def fetch_block_transaction_hashes(self, index):
        """Fetch transaction hashes in a block at height index"""
        command = b"blockchain.fetch_block_transaction_hashes"
        data = pack_block_index(index)
        error_code, data = await self._simple_request(command, data)
        if error_code:
            return error_code, None
        return error_code, unpack_table("32s", data)

    async def fetch_blockchain_transaction(self, txid):
        """Fetch transaction by txid (not including mempool)"""
        command = b"blockchain.fetch_transaction2"
        error_code, data = await self._simple_request(command,
                                                      bytes.fromhex(txid)[::-1])
        if error_code:
            return error_code, None
        return error_code, data

    async def fetch_mempool_transaction(self, txid):
        """Fetch transaction by txid (including mempool)"""
        command = b"transaction_pool.fetch_transaction2"
        error_code, data = await self._simple_request(command,
                                                      bytes.fromhex(txid)[::-1])
        if error_code:
            return error_code, None
        return error_code, data

    async def subscribe_scripthash(self, scripthash):
        """Subscribe to scripthash"""
        command = b"subscribe.key"
        decoded_address = unhexlify(scripthash)
        return await self._subscription_request(command, decoded_address)

    async def unsubscribe_scripthash(self, scripthash):
        """Unsubscribe scripthash"""
        # TODO: This call should ideally also remove the subscription
        # request from the RequestCollection.
        # This call solicits a final call from the server with an
        # `error::service_stopped` error code.
        command = b"unsubscribe.key"
        decoded_address = unhexlify(scripthash)
        return await self._simple_request(command, decoded_address)

    async def fetch_history4(self, scripthash, height=0):
        """Fetch history for given scripthash"""
        command = b"blockchain.fetch_history4"
        decoded_address = unhexlify(scripthash)
        error_code, raw_points = await self._simple_request(
            command, decoded_address + struct.pack("<I", height))
        if error_code:
            return error_code, None

        def make_tuple(row):
            kind, height, tx_hash, index, value = row
            return (
                kind,
                {
                    "hash": tx_hash,
                    "index": index
                },
                height,
                value,
                checksum(hash_to_hex_str(tx_hash), index),
            )

        rows = unpack_table("<BI32sIQ", raw_points)
        points = [make_tuple(row) for row in rows]
        correlated_points = Client.__correlate(points)
        # self.log.debug("history points: %s", points)
        # self.log.debug("history correlated: %s", correlated_points)
        # return error_code, self._sort_correlated_points(correlated_points)
        return error_code, correlated_points

    @staticmethod
    def _sort_correlated_points(points):
        """Sort by ascending height"""
        if len(points) < 2:
            return points
        return sorted(points, key=lambda x: list(x.values())[0]["height"])

    async def broadcast_transaction(self, rawtx):
        """Broadcast given raw transaction"""
        command = b"transaction_pool.broadcast"
        return await self._simple_request(command, rawtx)

    async def fetch_balance(self, scripthash):
        """Fetch balance for given scripthash"""
        error_code, history = await self.fetch_history4(scripthash)
        if error_code:
            return error_code, None

        utxo = Client.__receives_without_spends(history)
        return error_code, functools.reduce(
            lambda accumulator, point: accumulator + point["value"], utxo, 0)

    async def fetch_utxo(self, scripthash):
        """Find UTXO for given scripthash"""
        error_code, history = await self.fetch_history4(scripthash)
        if error_code:
            return error_code, None
        return error_code, Client.__receives_without_spends(history)

    async def subscribe_to_blocks(self, queue):
        asyncio.ensure_future(self._listen_for_blocks(queue))
        return queue

    async def _listen_for_blocks(self, queue):
        """Infinite loop for block subscription.
        Returns raw blocks as they're received.
        """
        while True:
            frame = await self._block_socket.recv_multipart()
            seq = struct.unpack("<H", frame[0])[0]
            height = struct.unpack("<I", frame[1])[0]
            block_data = frame[2]
            queue.put_nowait((seq, height, block_data))

    @staticmethod
    def __receives_without_spends(history):
        return (point for point in history if "spent" not in point)

    @staticmethod
    def __correlate(points):
        transfers, checksum_to_index = Client.__find_receives(points)
        transfers = Client.__correlate_spends_to_receives(
            points, transfers, checksum_to_index)
        return transfers

    @staticmethod
    def __correlate_spends_to_receives(points, transfers, checksum_to_index):
        for point in points:
            if point[0] == 1:  # receive
                continue

            spent = {
                "hash": point[1]["hash"],
                "height": point[2],
                "index": point[1]["index"],
            }
            if point[3] not in checksum_to_index:
                transfers.append({"spent": spent})
            else:
                transfers[checksum_to_index[point[3]]]["spent"] = spent

        return transfers

    @staticmethod
    def __find_receives(points):
        transfers = []
        checksum_to_index = {}

        for point in points:
            if point[0] == 0:  # spent
                continue

            transfers.append({
                "received": {
                    "hash": point[1]["hash"],
                    "height": point[2],
                    "index": point[1]["index"],
                },
                "value": point[3],
            })

            checksum_to_index[point[4]] = len(transfers) - 1

        return transfers, checksum_to_index
