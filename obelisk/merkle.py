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
"""Module for calculating merkle branches"""
from math import ceil, log

from obelisk.util import double_sha256, hash_to_hex_str


def branch_length(hash_count):  # pragma: no cover
    """Return the length of a merkle branch given the number of hashes"""
    if not isinstance(hash_count, int):
        raise TypeError("hash_count must be an integer")
    if hash_count < 1:
        raise ValueError("hash_count must be at least 1")
    return ceil(log(hash_count, 2))


def merkle_branch_and_root(hashes, index, length=None):
    """Return a (merkle branch, merkle_root) pair given hashes, and the
    index of one of those hashes.
    """
    hashes = list(hashes)
    if not isinstance(index, int):
        raise TypeError("index must be an integer")  # pragma: no cover
    # This also asserts hashes is not empty
    if not 0 <= index < len(hashes):
        raise ValueError("index out of range")  # pragma: no cover
    natural_length = branch_length(len(hashes))
    if length is None:
        length = natural_length
    else:  # pragma: no cover
        if not isinstance(length, int):
            raise TypeError("length must be an integer")
        if length < natural_length:
            raise ValueError("length out of range")

    branch = []
    for _ in range(length):
        if len(hashes) & 1:
            hashes.append(hashes[-1])
        branch.append(hashes[index ^ 1])
        index >>= 1
        hashes = [
            double_sha256(hashes[n] + hashes[n + 1])
            for n in range(0, len(hashes), 2)
        ]
    return branch, hashes[0]


def merkle_branch(tx_hashes, tx_pos):
    """Return a merkle branch given hashes and the tx position"""
    branch, _ = merkle_branch_and_root(tx_hashes, tx_pos)
    return [hash_to_hex_str(h) for h in branch]
