# -*- coding: utf-8 -*-

# Copyright (c) 2014, 2015 Metaswitch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
calico.election
~~~~~~~~~~~~

Calico election code.
"""
import etcd
from etcd import EtcdKeyNotFound
import gevent
import gevent.lock
import logging
import time
from urllib3 import Timeout
import urllib3.exceptions
from urllib3.exceptions import ReadTimeoutError, ConnectTimeoutError
import os

_log = logging.getLogger(__name__)

class Elector(object):
    """
    Class that manages elections.
    """
    def __init__(self, server_id, election_key,
                 etcd_host="localhost", etcd_port=4001,
                 interval=30, ttl=60):

        self._server_id = server_id
        self._key = election_key
        self._etcd_host = etcd_host
        self._etcd_port = int(etcd_port)
        self._interval = int(interval)
        self._ttl = int(ttl)

        assert(self._interval > 0)
        assert(self._ttl > self._interval)

        self._master = False
        self._mutex = gevent.lock.Semaphore()

        gevent.spawn(self._run)

    def _run(self):

        interval = 0

        while True:
            # Sleep if this is not the first time round the loop, then recreate
            # the client.
            gevent.sleep(interval)
            interval = self._interval
            client = etcd.Client(host=self._etcd_host, port=self._etcd_port)

            try:
                response = client.read(self._key)
                index = response.etcd_index
            except EtcdKeyNotFound:
                _log.debug("Try to become the master - no entry"),

                self._become_master(client)
                # If _become_master returns, we failed and should continue.
                continue
            except:
                # Some kind of exception. Try again later.
                _log.warning("Failed to read elected master",
                             exc_info=True)
                continue

            _log.debug("ID of elected master is : %s", response.value)

            while True:
                # We know another instance is the master. Wait until something
                # changes, giving long enough that it really should do.
                try:
                    response = client.read(self._key,
                                           wait=True,
                                           waitIndex=index + 1,
                                           timeout=Timeout(connect=self._interval,
                                                           read=self._ttl * 2))
                    index = response.etcd_index

                except (ReadTimeoutError, SocketTimeout) as e:
                    # Unexpected timeout - reconnect.
                    _log.debug("Read from etcd timed out (%r), retrying.", e)
                    break
                except:
                    # Something bad and unexpected. Log but just reconnect.
                    _log.warning("Unexpected error waiting for change in elected master",
                                 exc_info=True)
                    break

                if response.action == "delete":
                    # Deleted - try and become the master. If we fail, reconnect.
                    self._become_master(client)
                    break


    def _become_master(self, client):
        """
        Function to become the master. Returns if it fails, but if it succeeds
        never returns, and continually loops updating the key as necessary.
        param: etcd.Client: etcd client to use
        raises: Nothing; terminates on error.
        """
        id_string = "%s:%d:%s" % (self._server_id, os.getpid(), int(time.time()))

        try:
            client.write(self._key, id_string,
                         ttl=self._ttl, prevExists=False)
        except:
            # Got an error, so give up right away.
            _log.warning("Failed to become elected master - key %s",
                         self._key, exc_info=True)
            return

        _log.warning("Successfully become master - key %s, value %s",
                     self._key, id_string)

        self._mutex.acquire()
        self._master = True
        self._mutex.release()

        while True:
            try:
                gevent.sleep(self._interval)
                client.write(self._key, id_string, ttl=self._ttl,
                             prevValue=id_string)
            except:
                # If we get an exception, just terminate
                _log.exception("Exception raised in election - terminating")
                os._exit(1)

    def master(self):
        """
        Am I the master?
        returns: True if this is the master.
        """
        self._mutex.acquire()
        master = self._master
        self._mutex.release()
        return master
