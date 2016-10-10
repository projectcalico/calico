# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
felix.test.check_iptables
~~~~~~~~~~~~~~~~~~~~~~~~~

Manual test script to check our assumptions about iptables.  Not a test case
because it needs to be run as root.
"""
import logging
from subprocess import check_call, check_output, CalledProcessError, Popen, PIPE
import time

_log = logging.getLogger(__name__)

DELAY = 0.1

CHAIN_A = "chk-ipt-chain-a"
CHAIN_B = "chk-ipt-chain-b"
ALL_CHAINS = [CHAIN_A, CHAIN_B]

CREATE_A_PREAMBLE = """*filter
:chk-ipt-chain-a -
-A chk-ipt-chain-a -j DROP
"""

CREATE_B_PREAMBLE = """*filter
:chk-ipt-chain-b -
-A chk-ipt-chain-b -j DROP
"""
CREATE_B_RAW_PREAMBLE = """*raw
:chk-ipt-chain-b -
-A chk-ipt-chain-b -j DROP
"""
COMMIT = "COMMIT\n"

def ensure_no_chain(table, chain):
    try:
        try:
            check_call(["iptables", "-t", table, "--flush", chain],
                       stderr=open("/dev/null", "w"),
                       stdout=open("/dev/null", "w"))
        except CalledProcessError:
            pass
        check_call(["iptables", "-t", table, "--delete-chain", chain],
                       stderr=open("/dev/null", "w"),
                       stdout=open("/dev/null", "w"))
    except CalledProcessError:
        pass
    assert not chain_exists(table, chain), "Chain %s still exists" % chain


def list_chains(table):
    output = check_output(["iptables", "-t", table, "--list"]).splitlines()
    chains = [l.split(" ")[1] for l in output if l.startswith("Chain ")]
    return chains


def chain_exists(table, chain):
    return chain in list_chains(table)


def delete_all():
    # Start off by deleting all chains.
    for table in ("filter", "raw"):
        for chain in ALL_CHAINS:
            ensure_no_chain("filter", chain)


def open_ipt_restore():
    return Popen(["iptables-restore", "--noflush"], stdin=PIPE)


def write_and_wait(proc, input):
    proc.stdin.write(input)
    proc.stdin.flush()
    time.sleep(DELAY)


def write_and_close(proc, input):
    proc.stdin.write(input)
    proc.stdin.flush()
    proc.stdin.close()


def main():
    try:
        print "-------"
        print "Test: Basic, sequential creation of chains."
        print "-------"
        delete_all()

        iptr_a = open_ipt_restore()
        write_and_wait(iptr_a, CREATE_A_PREAMBLE)
        write_and_close(iptr_a, COMMIT)
        rc_a = iptr_a.wait()

        iptr_b = open_ipt_restore()
        write_and_wait(iptr_b, CREATE_B_PREAMBLE)
        write_and_close(iptr_b, COMMIT)
        rc_b = iptr_b.wait()

        print "Create A RC =", rc_a
        print "Create B RC =", rc_b
        print "Chain A exists:", chain_exists("filter", CHAIN_A)
        print "Chain B exists:", chain_exists("filter", CHAIN_B)
        assert rc_a == 0
        assert rc_b == 0
        assert chain_exists("filter", CHAIN_A)
        assert chain_exists("filter", CHAIN_B)
        print "OK"

        print "-------"
        print "Test: Concurrent create in different tables no interaction."
        print "-------"
        delete_all()
        iptr_a = open_ipt_restore()
        iptr_b = open_ipt_restore()
        write_and_wait(iptr_a, CREATE_A_PREAMBLE)
        write_and_wait(iptr_b, CREATE_B_RAW_PREAMBLE)
        write_and_close(iptr_b, COMMIT)
        time.sleep(0.1)
        write_and_close(iptr_a, COMMIT)
        rc_a = iptr_a.wait()
        rc_b = iptr_b.wait()
        print "Create A RC =", rc_a
        print "Create B RC =", rc_b
        print "Chain A exists:", chain_exists("filter", CHAIN_A)
        print "Chain B exists:", chain_exists("raw", CHAIN_B)
        assert rc_a == 0
        assert rc_b == 0
        assert chain_exists("filter", CHAIN_A)
        assert chain_exists("raw", CHAIN_B)
        print "OK"

        print "-------"
        print "Test: Concurrent creation of different chains using ipt-restore."
        print "-------"
        delete_all()
        iptr_a = open_ipt_restore()
        iptr_b = open_ipt_restore()
        write_and_wait(iptr_a, CREATE_A_PREAMBLE)
        write_and_wait(iptr_b, CREATE_B_PREAMBLE)
        write_and_close(iptr_b, COMMIT)
        time.sleep(0.1)
        write_and_close(iptr_a, COMMIT)
        rc_a = iptr_a.wait()
        rc_b = iptr_b.wait()
        print "Create A RC =", rc_a
        print "Create B RC =", rc_b
        print "Chain A exists:", chain_exists("filter", CHAIN_A)
        print "Chain B exists:", chain_exists("filter", CHAIN_B)
        assert rc_a != 0 or rc_b != 0, "Expected one or other commit to fail."
        print "OK"

        print "-------"
        print "Test: Concurrent creation of same chain using ipt-restore."
        print "-------"
        delete_all()
        iptr_a = open_ipt_restore()
        iptr_a2 = open_ipt_restore()
        write_and_wait(iptr_a, CREATE_A_PREAMBLE)
        write_and_wait(iptr_a2, CREATE_A_PREAMBLE)
        write_and_close(iptr_a2, COMMIT)
        time.sleep(0.1)
        write_and_close(iptr_a, COMMIT)
        rc_a = iptr_a.wait()
        rc_a2 = iptr_a2.wait()
        print "Create A RC =", rc_a
        print "Create A2 RC =", rc_a2
        print "Chain A exists:", chain_exists("filter", CHAIN_A)
        assert chain_exists("filter", CHAIN_A)
        assert rc_a != 0 or rc_a2 != 0, "Expected one or other commit to fail."
        print "OK"

        print "-------"
        print "Test: iptables create/append while restore in progress"
        print "-------"
        delete_all()
        iptr_a = open_ipt_restore()
        write_and_wait(iptr_a, CREATE_A_PREAMBLE)
        try:
            check_call(["iptables", "-t", "filter", "-N", CHAIN_B])
            check_call(["iptables", "-t", "filter", "-A", CHAIN_B])
        except CalledProcessError as e:
            print "Expected to be able to create chain B while iptables-restore " \
                  "running: %r" % e
            raise AssertionError("Failed to run iptables while iptables-restore "
                                 "active")
        write_and_close(iptr_a, COMMIT)
        rc_a = iptr_a.wait()
        print "Create A RC =", rc_a
        print "Chain A exists:", chain_exists("filter", CHAIN_A)
        print "Chain B exists:", chain_exists("filter", CHAIN_B)
        assert chain_exists("filter", CHAIN_B), "iptables should have succeeded"
        assert rc_a != 0, "Expected commit to fail due to dirty read."
        assert not chain_exists("filter", CHAIN_A)
        print "OK"
    finally:
        print "-------"
        print "Cleaning up..."
        delete_all()

if __name__ == "__main__":
    main()
