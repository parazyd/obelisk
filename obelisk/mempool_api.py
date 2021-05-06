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
"""mempool.space API functions"""
import json
from http.client import HTTPSConnection


def get_mempool_fee_estimates():
    conn = HTTPSConnection("mempool.space")
    conn.request("GET", "/api/v1/fees/recommended")
    res = conn.getresponse()

    if res.status != 200:
        return None

    return json.load(res)
