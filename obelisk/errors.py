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
"""JSON-RPC errors
https://www.jsonrpc.org/specification#error_object
"""

ERRORS = {
    "invalidparams": {
        "error": {
            "code": -32602,
            "message": "invalid parameters"
        }
    },
    "internalerror": {
        "error": {
            "code": -32603,
            "message": "internal error"
        }
    },
    "parseerror": {
        "error": {
            "code": -32700,
            "message": "parse error"
        }
    },
    "invalidrequest": {
        "error": {
            "code": -32600,
            "message": "invalid request"
        }
    },
    "nomethod": {
        "error": {
            "code": -32601,
            "message": "method not found"
        }
    },
    "protonotsupported": {
        "error": {
            "code": -32100,
            "message": "client protocol version is not supported",
        }
    },
}
