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
from greenlet import GreenletExit
import random
import etcd
import eventlet
from httplib import HTTPException
import logging
from socket import timeout as SocketTimeout
from urllib3 import Timeout
from urllib3.exceptions import HTTPError

import os

_log = logging.getLogger(__name__)


ETCD_DELETE_ACTIONS = set(["delete", "expire", "compareAndDelete"])


class RestartElection(Exception):
    """
    Exception indicating that we should start our leader election over.
    """
    pass


class Elector(object):
    def __init__(self, client, server_id, election_key,
                 interval=30, ttl=60):
        """
        Class that manages elections.

        :param client: etcd client object
        :param server_id: Server ID. Must be unique to this server, and should
                          take a value that is meaningful in logs (e.g.
                          hostname)
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
        self._stopped = False

        if self._interval <= 0:
            raise ValueError("Interval %r is <= 0" % interval)

        if self._ttl <= self._interval:
            raise ValueError("TTL %r is <= interval %r" % (ttl, interval))

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
            while not self._stopped:
                try:
                    self._vote()
                except RestartElection:
                    # Something failed, and wants us just to go back to the
                    # beginning.
                    pass
                # In case we're repeatedly failing, sleep a little before we
                # retry.
                retry_time = 1 + (5 * random.random())
                _log.info("Retrying leader election in %.1f seconds",
                          retry_time)
                eventlet.sleep(retry_time)
        except ElectorStopped:
            _log.info("Elector told to stop.")
            raise
        except BaseException as e:
            # Election greenlet failed. Log but reraise.
            _log.exception("Election greenlet exiting: %r", e)
            raise
        finally:
            self._attempt_step_down()

    def _vote(self):
        """
        Main election thread routine to reconnect and perform election.
        """
        try:
            response = self._etcd_client.read(self._key,
                                              timeout=self._interval)
            index = response.etcd_index
        except etcd.EtcdKeyNotFound:
            _log.debug("Try to become the master - key not found")
            self._become_master()
            assert False, "_become_master() should not return."
        except (SocketTimeout,
                HTTPError,
                HTTPException,
                etcd.EtcdException) as e:
            # Something bad and unexpected. Log and reconnect.
            self._log_exception("read current master", e)
            return

        _log.debug("ID of elected master is : %s", response.value)

        while not self._stopped:
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
            except etcd.EtcdKeyNotFound:
                # It should be impossible for somebody to delete the object
                # without us getting the delete action, but safer to handle it.
                _log.warning("Implausible vanished key - become master")
                self._become_master()
            except (SocketTimeout,
                    HTTPError,
                    HTTPException,
                    etcd.EtcdException) as e:
                # Something bad and unexpected. Log and reconnect.
                self._log_exception("wait for master change", e)
                return

            if (response.action in ETCD_DELETE_ACTIONS or
                    response.value is None):
                # Deleted - try and become the master.
                _log.info("Leader etcd key went away, attempting to become "
                          "the elected master")
                self._become_master()

    def _become_master(self):
        """
        Function to become the master. Never returns, and continually loops
        updating the key as necessary.

        raises: RestartElection if it fails to become master (e.g race
                conditions). In this case, some other process has become
                master.
                Any other error from etcd is not caught in this routine.
        """

        try:
            self._etcd_client.write(self._key,
                                    self.id_string,
                                    ttl=self._ttl,
                                    prevExist=False,
                                    timeout=self._interval)
        except Exception as e:
            # We could be smarter about what exceptions we allow, but any kind
            # of error means we should give up, and safer to have a broad
            # except here. Log and reconnect.
            self._log_exception("become elected master", e)
            raise RestartElection()

        _log.info("Successfully become master - key %s, value %s",
                  self._key, self.id_string)

        self._master = True

        while not self._stopped:
            try:
                self._etcd_client.write(self._key,
                                        self.id_string,
                                        ttl=self._ttl,
                                        prevValue=self.id_string,
                                        timeout=self._interval)
            except Exception as e:
                # This is a pretty broad except statement, but anything going
                # wrong means this instance gives up being the master.
                self._master = False
                self._log_exception("renew master role", e)
                raise RestartElection()

            eventlet.sleep(self._interval)
        raise RestartElection()

    def _log_exception(self, failed_to, exc):
        """
        Log out an exception we got from a call to etcd.

        :param failed_to: Snippet to include, such as "become master".
        """
        if isinstance(exc, etcd.EtcdClusterIdChanged):
            _log.warning("etcd cluster ID changed while trying to %s, "
                         "the etcd cluster may have been rebuilt.", failed_to)
        elif isinstance(exc, (etcd.EtcdException, HTTPError, HTTPException,
                              SocketTimeout)):
            # Expected errors (with good messages): timeouts and connection
            # failures.  Don't log stack traces to avoid cluttering the log.
            _log.warning("Failed to %s - key %s: %r", failed_to,
                         self._key, exc)
        else:
            # Genuinely unexpected errors.
            _log.exception("Unexpected error, failed to %s - key %s",
                           failed_to, self._key)

    @property
    def id_string(self):
        return "%s:%d" % (self._server_id, os.getpid())

    def _attempt_step_down(self):
        try:
            self._etcd_client.delete(self._key,
                                     prevValue=self.id_string,
                                     timeout=self._interval)
        except Exception:
            # Broad except because we're already on an error path.  The key
            # will expire anyway.
            _log.exception("Failed to step down as master.  Ignoring.")

    def master(self):
        """
        Am I the master?
        returns: True if this is the master.
        """
        return self._master and not self._stopped

    def stop(self):
        self._stopped = True
        if self._greenlet and not self._greenlet.dead:
            self._greenlet.kill(ElectorStopped(), None, None)
            try:
                # It should die very quickly.
                eventlet.with_timeout(10, self._greenlet.wait)
            except eventlet.Timeout:
                # Looks like we've leaked the greenlet somehow.
                _log.error("Timeout while waiting for the greenlet to die.")
                raise RuntimeError("Failed to kill Elector greenlet.")
            except ElectorStopped:
                pass  # Expected


class ElectorStopped(GreenletExit):
    """
    Custom exception used to stop our Elector.  Used to distinguish our
    kill() call from any other potential GreenletExit exception.
    """
    pass
