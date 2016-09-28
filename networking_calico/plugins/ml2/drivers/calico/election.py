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
Calico election code.
"""
import etcd
import eventlet
from greenlet import GreenletExit
import os
import random
import re
from urllib3 import Timeout

# Fix urllib3 unvendoring error so that python-etcd can catch exceptions raised
# by urllib3.  See networking_calico/agent/__init__.py for the full
# explanation.
import sys
if sys.modules["urllib3"].exceptions is not sys.modules["urllib3.exceptions"]:
    sys.modules["urllib3"].exceptions = sys.modules["urllib3.exceptions"]

try:  # Icehouse, Juno
    from neutron.openstack.common import log
except ImportError:  # Kilo
    from oslo_log import log

LOG = log.getLogger(__name__)


ETCD_DELETE_ACTIONS = set(["delete", "expire", "compareAndDelete"])


class RestartElection(Exception):
    """Exception indicating that we should start our leader election over."""
    pass


class Elector(object):
    def __init__(self, client, server_id, election_key,
                 interval=30, ttl=60):
        """Class that manages elections.

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
        """Main election thread run routine.

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
                retry_time = 1 + random.random()
                LOG.info("Retrying leader election in %.1f seconds",
                         retry_time)
                eventlet.sleep(retry_time)
        except ElectorStopped:
            LOG.info("Elector told to stop.")
            raise
        except BaseException as e:
            # Election greenlet failed. Log but reraise.
            LOG.exception("Election greenlet exiting: %r", e)
            # Kill (and so restart) the Neutron server as a whole.
            # This is an unhandled situation, so we don't know what
            # the situation is - but it is certain that the Calico
            # driver does not function correctly once this leader
            # election thread has died.  Hence our best option is to
            # restart the whole Neutron server.
            sys.exit(1)
            # Just in case we're still here - reraise the exception.
            raise
        finally:
            self._attempt_step_down()

    def _vote(self):
        """Main election thread routine to reconnect and perform election."""
        try:
            response = self._etcd_client.read(self._key,
                                              timeout=self._interval)
            index = response.etcd_index
        except etcd.EtcdKeyNotFound:
            LOG.debug("Try to become the master - key not found")
            self._become_master()
            assert False, "_become_master() should not return."
        except etcd.EtcdException as e:
            # Something bad and unexpected. Log and reconnect.
            self._log_exception("read current master", e)
            return

        LOG.debug("ID of elected master is : %s", response.value)
        if response.value:
            # If we happen to be on the same server, check if the master
            # process is still alive.
            self._check_master_process(response.value)

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
                LOG.warning("Implausible vanished key - become master")
                self._become_master()
            except etcd.EtcdEventIndexCleared:
                # etcd only keeps a buffer of 1000 events. If that buffer wraps
                # before the master refreshes, we get EtcdEventIndexCleared.
                # Simply return, which will retry the read and get the new
                # etcd index.
                LOG.info("etcd index cleared; aborting poll to re-read key.")
                return
            except etcd.EtcdException as e:
                # Something bad and unexpected. Log and reconnect.
                self._log_exception("wait for master change", e)
                return
            LOG.debug("Election key action: %s; new value %s",
                      response.action, response.value)
            if (response.action in ETCD_DELETE_ACTIONS or
                    response.value is None):
                # Deleted - try and become the master.
                LOG.info("Leader etcd key went away, attempting to become "
                         "the elected master")
                self._become_master()

    def _check_master_process(self, master_id):
        """_check_master_process

        If the master happens to be on our host, checks if its process is
        still alive.  If it is not, cleans up the now-stale election key.

        :param master_id: Value loaded from the election key.
        """
        # Defensive. In case we ever change the master ID format, only parse
        # it if it looks like what we expect.
        match = re.match(r"^(?P<host>[^:]+):(?P<pid>\d+)$", master_id)
        if not match:
            LOG.warn("Unable to parse master ID: %r.", master_id)
            return
        host = match.group("host")
        pid = int(match.group("pid"))
        LOG.debug("Parsed key as host = %s, PID = %s", host, pid)
        if host == self._server_id:
            # Check if the PID is still running.
            LOG.debug("Previous master was on this server %s", host)
            if os.path.exists("/proc/%s" % pid):
                LOG.debug("Master still running")
            else:
                LOG.warn("Master was on this server but cannot find its "
                         "PID in /proc.  Removing stale election key.")
                try:
                    self._etcd_client.delete(self._key,
                                             prevValue=master_id)
                except etcd.EtcdException as e:
                    LOG.warn("Failed to remove stale key from dead "
                             "master: %r", e)
                raise RestartElection()

    def _become_master(self):
        """_become_master

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

        LOG.info("Successfully become master - key %s, value %s",
                 self._key, self.id_string)

        self._master = True

        try:
            while not self._stopped:
                try:
                    LOG.info("Refreshing master role")
                    self._etcd_client.write(self._key,
                                            self.id_string,
                                            ttl=self._ttl,
                                            prevValue=self.id_string,
                                            timeout=self._interval / 3)
                    LOG.info("Refreshed master role")
                except Exception as e:
                    # This is a pretty broad except statement, but anything
                    # going wrong means this instance gives up being the
                    # master.
                    self._log_exception("renew master role", e)
                    raise RestartElection()
                eventlet.sleep(self._interval)
        finally:
            LOG.info("Exiting master refresh loop, no longer the master")
            self._master = False
        raise RestartElection()

    def _log_exception(self, failed_to, exc):
        """Log out an exception we got from a call to etcd.

        :param failed_to: Snippet to include, such as "become master".
        """
        if isinstance(exc, etcd.EtcdClusterIdChanged):
            LOG.warning("etcd cluster ID changed while trying to %s, "
                        "the etcd cluster may have been rebuilt.", failed_to)
        elif isinstance(exc, etcd.EtcdException):
            # Expected errors (with good messages): timeouts and connection
            # failures.  Don't log stack traces to avoid cluttering the log.
            LOG.warning("Failed to %s - key %s: %r", failed_to,
                        self._key, exc)
        else:
            # Genuinely unexpected errors.
            LOG.exception("Unexpected error, failed to %s - key %s",
                          failed_to, self._key)

    @property
    def id_string(self):
        return "%s:%d" % (self._server_id, os.getpid())

    def _attempt_step_down(self):
        self._master = False
        try:
            self._etcd_client.delete(self._key,
                                     prevValue=self.id_string,
                                     timeout=self._interval)
        except Exception:
            # Broad except because we're already on an error path.  The key
            # will expire anyway.
            LOG.exception("Failed to step down as master.  Ignoring.")

    def master(self):
        """Am I the master?

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
                LOG.error("Timeout while waiting for the greenlet to die.")
                raise RuntimeError("Failed to kill Elector greenlet.")
            except ElectorStopped:
                pass  # Expected


class ElectorStopped(GreenletExit):
    """ElectorStopped

    Custom exception used to stop our Elector.  Used to distinguish our
    kill() call from any other potential GreenletExit exception.
    """
    pass
