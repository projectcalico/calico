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
import eventlet
from httplib import HTTPException
import logging
from socket import timeout as SocketTimeout
import time
from urllib3 import Timeout
from urllib3.exceptions import ReadTimeoutError, ConnectTimeoutError, HTTPError

import os

_log = logging.getLogger(__name__)

class ElectionReconnect(Exception):
    """
    Exception indicating that an error occurred, and we should try reconnect.
    """
    pass

class Elector(object):
    def __init__(self, client, server_id, election_key,
                 interval=30, ttl=60):
        """
        Class that manages elections.

        :param client: etcd client object
        :param server_id: Server ID. Must be unique to this server, and should
                       take a value that is meaningful in logs (e.g. hostname)
        :param election_key: The etcd key used in the election - e.g.
                             "/calico/v1/election"
        :param interval: Interval (seconds) between checks on etcd. Must be > 0
        :param ttl: Time to live (seconds) for etcd values. Must be > interval.
        """
        self._etcd_client = client
        self._server_id = server_id
        self._key = election_key
        self._interval = int(interval)
        self._ttl = int(ttl)

        if self._interval <= 0:
            raise AssertionError("Interval %r is <= 0" % interval)

        if self._ttl <= self._interval:
            raise AssertionError("TTL %r is <= interval %r" % (ttl, interval))

        # Used to track whether or not this is the first iteration of the
        # attempts to test who is master.
        self._first_iteration = True

        # Is this the master? To start with, no
        self._master = False

        # Keep the greenlet ID handy to ease UT.
        self._greenlet = eventlet.spawn(self._run)

    def _run(self):
        """
        Main election thread run routine.

        The slightly artificial split between this and _vote is mostly so that
        we can easily catch and log any exception that takes out the greenlet.
        """
        try:
            while True:
                try:
                    self._vote()
                except ElectionReconnect:
                    # Something failed, and wants us just to go back to the
                    # beginning.
                    pass

        except:
            # Election greenlet failed. Log but reraise.
            _log.exception("Election greenlet exiting")
            raise

    def _vote(self):
        """
        Main election thread routine to reconnect and perform election.
        """
        # Sleep only if this is not the first time round the loop.
        if self._first_iteration:
            self._first_iteration = False
        else:
            eventlet.sleep(self._interval)

        try:
            response = self._etcd_client.read(self._key)
            index = response.etcd_index
        except etcd.EtcdKeyNotFound:
            _log.debug("Try to become the master - not found")
            self._become_master()
        except (etcd.EtcdException, ReadTimeoutError, SocketTimeout,
                ConnectTimeoutError, HTTPError,
                etcd.EtcdClusterIdChanged, etcd.EtcdEventIndexCleared,
                HTTPException):
            # Some kind of exception. Try again later.
            _log.warning("Failed to read elected master",
                         exc_info=True)
            return

        _log.debug("ID of elected master is : %s", response.value)

        while True:
            # We know another instance is the master. Wait until something
            # changes, giving long enough that it really should do (i.e. we
            # expect this read always to return, never to time out).
            try:
                response = self._etcd_client.read(self._key,
                                                  wait=True,
                                                  waitIndex=index + 1,
                                                  timeout=Timeout(
                                                      connect=self._interval,
                                                      read=self._ttl * 2))
                index = response.etcd_index

            except (ReadTimeoutError, SocketTimeout,
                    ConnectTimeoutError) as e:
                # Unexpected timeout - reconnect.
                _log.debug("Read from etcd timed out (%r), retrying.", e)
                return
            except (etcd.EtcdException, HTTPError, HTTPException,
                    etcd.EtcdClusterIdChanged, etcd.EtcdEventIndexCleared):
                # Something bad and unexpected. Log and reconnect.
                _log.warning("Unexpected error waiting for change in elected master",
                             exc_info=True)
                return
            except etcd.EtcdKeyNotFound:
                # It should be impossible for somebody to delete the object
                # without us getting the delete action, but safer to handle it.
                _log.warning("Implausible vanished key - become master")
                self._become_master()

            if response.action == "delete":
                # Deleted - try and become the master.
                _log.debug("Attempting to become the elected master")
                self._become_master()

    def _become_master(self,):
        """
        Function to become the master. Never returns, and continually loops
        updating the key as necessary.

        param: etcd.Client: etcd client to use
        raises: ElectionReconnect if it fails to become master (e.g race
                conditions). In this case, some other process has become
                master.
                Any other error from etcd is not caught in this routine.
        """
        id_string = "%s:%d:%s" % (self._server_id, os.getpid(), int(time.time()))

        try:
            self._etcd_client.write(self._key, id_string,
                                    ttl=self._ttl, prevExists=False)
        except Exception:
            # We could be smarter about what exceptions we allow, but any kind
            # of error means we should give up, and safer to have a broad
            # except here.
            _log.warning("Failed to become elected master - key %s",
                         self._key, exc_info=True)
            raise ElectionReconnect()

        _log.warning("Successfully become master - key %s, value %s",
                     self._key, id_string)

        self._master = True

        while True:
            eventlet.sleep(self._interval)
            try:
                self._etcd_client.write(self._key, id_string, ttl=self._ttl,
                                        prevValue=id_string)
            except Exception:
                # This is a pretty broad except statement, but anything going
                # wrong means this instance gives up being the master.
                self._master = False
                raise

    def master(self):
        """
        Am I the master?
        returns: True if this is the master.
        """
        return self._master
