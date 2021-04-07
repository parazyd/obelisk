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
import struct
from random import randint

import zmq
import zmq.asyncio

from libbitcoin_errors import make_error_code, ErrorCode


def create_random_id():
    """Generate a random request ID"""
    max_uint32 = 4294967295
    return randint(0, max_uint32)


class ClientSettings:
    """Class implementing ZMQ client settings"""
    def __init__(self, timeout=10, context=None, loop=None):
        self._timeout = timeout
        self._context = context
        self._loop = loop

    @property
    def context(self):
        """ZMQ context property"""
        if not self.context:
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
                f"DEBUG: RequestCollection unhandled response {response.command}:{response.request_id}"
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
        return await self._wait_for_response(await
                                             self._request(command, data))

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