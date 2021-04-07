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
""" Cryptographic hash functions and helpers """
import hashlib

_sha256 = hashlib.sha256


def sha256(inp):
    """ Simple wrapper of hashlib sha256. """
    return _sha256(inp).digest()


def double_sha256(inp):
    """ sha256 of sha256, as used extensively in bitcoin """
    return sha256(sha256(inp))


def hash_to_hex_str(inp):
    """Convert a big-endian binary hash to displayed hex string.
    Display form of a binary hash is reversed and converted to hex.
    """
    return bytes(reversed(inp)).hex()
