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
"""Utility functions"""
import hashlib
from binascii import hexlify

_sha256 = hashlib.sha256


def is_integer(val):
    """Check if val is of type int"""
    return isinstance(val, int)


def is_non_negative_integer(val):
    """Check if val is of type int and non-negative"""
    if is_integer(val):
        return val >= 0
    return False


def is_boolean(val):
    """Check if val is of type bool"""
    return isinstance(val, bool)


def is_hex_str(text):
    """Check if text is a hex string"""
    if not isinstance(text, str):
        return False
    try:
        b = bytes.fromhex(text)
    except:  # pylint: disable=W0702
        return False
    # Forbid whitespaces in text:
    if len(text) != 2 * len(b):
        return False
    return True


def is_hash256_str(text):
    """Check if text is a sha256 hash"""
    if not isinstance(text, str):
        return False
    if len(text) != 64:
        return False
    return is_hex_str(text)


def safe_hexlify(val):
    """hexlify and return a string"""
    return str(hexlify(val), "utf-8")


def bh2u(val):
    """
    str with hex representation of a bytes-like object

    >>> x = bytes((1, 2, 10))
    >>> bh2u(x)
    '01020A'
    """
    return val.hex()


def block_to_header(block):
    """Return block header from raw block"""
    if not isinstance(block, (bytes, bytearray)):
        raise ValueError("block is not of type bytes/bytearray")
    # TODO: check endianness
    block_header = block[:80]
    # version = block_header[:4]
    # prev_merkle_root = block_header[4:36]
    # merkle_root = block_header[36:68]
    # timestamp = block_header[68:72]
    # bits = block_header[72:76]
    # nonce = block_header[76:80]
    return block_header


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
