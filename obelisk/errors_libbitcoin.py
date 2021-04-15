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
"""Enumerated error codes that can be returned by libbitcoin"""
from enum import Enum


def make_error_code(ec):
    """Return ErrorCode from ec"""
    if not ec:
        return None
    return ErrorCode(ec)


class ErrorCode(Enum):
    """libbitcoin error codes"""

    # general codes
    success = 0
    deprecated1 = 6
    unknown = 43
    not_found = 3
    file_system = 42
    not_implemented = 4
    oversubscribed = 71

    # network
    service_stopped = 1
    operation_failed = 2
    resolve_failed = 7
    network_unreachable = 8
    address_in_use = 9
    listen_failed = 10
    accept_failed = 11
    bad_stream = 12
    channel_timeout = 13
    address_blocked = 44
    channel_stopped = 45
    peer_throttling = 73

    # database
    store_block_duplicate = 66
    store_block_invalid_height = 67
    store_block_missing_parent = 68
    store_lock_failure = 85
    store_incorrect_state = 86

    # blockchain
    duplicate_block = 51
    orphan_block = 5
    invalid_previous_block = 24
    insufficient_work = 48
    duplicate_transaction = 84
    orphan_transaction = 14
    transaction_version = 17
    insufficient_fee = 70
    stale_chain = 75
    dusty_transaction = 76

    # check header
    invalid_proof_of_work = 26
    futuristic_timestamp = 27

    # accept header
    checkpoints_failed = 35
    invalid_block_version = 36
    incorrect_proof_of_work = 32
    timestamp_too_early = 33

    # check block
    block_size_limit = 50
    empty_block = 47
    first_not_coinbase = 28
    extra_coinbases = 29
    internal_duplicate = 49
    block_internal_double_spend = 15
    forward_reference = 79
    merkle_mismatch = 31
    block_legacy_sigop_limit = 30

    # accept block
    block_non_final = 34
    coinbase_height_mismatch = 37
    coinbase_value_limit = 41
    block_embedded_sigop_limit = 52
    invalid_witness_commitment = 25
    block_weight_limit = 82

    # check transaction
    empty_transaction = 20
    previous_output_null = 23
    spend_overflow = 21
    invalid_coinbase_script_size = 22
    coinbase_transaction = 16
    transaction_internal_double_spend = 72
    transaction_size_limit = 53
    transaction_legacy_sigop_limit = 54

    # accept transaction
    transaction_non_final = 74
    premature_validation = 69
    unspent_duplicate = 38
    missing_previous_output = 19
    double_spend = 18
    coinbase_maturity = 46
    spend_exceeds_value = 40
    transaction_embedded_sigop_limit = 55
    sequence_locked = 78
    transaction_weight_limit = 83

    # connect input
    invalid_script = 39
    invalid_script_size = 56
    invalid_push_data_size = 57
    invalid_operation_count = 58
    invalid_stack_size = 59
    invalid_stack_scope = 60
    invalid_script_embed = 61
    invalid_signature_encoding = 62
    deprecated2 = 63
    incorrect_signature = 64
    unexpected_witness = 77
    invalid_witness = 80
    dirty_witness = 81
    stack_false = 65

    # http
    http_invalid_request = 90
    http_method_not_found = 91
    http_internal_error = 92
