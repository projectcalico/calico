# -*- coding: utf-8 -*-
# Copyright (c) 2014, 2015 Metaswitch Networks
# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
from etcd3gw.exceptions import Etcd3Exception
import eventlet
import greenlet
import os
import random
import re
import socket
import sys

from networking_calico.common import config as calico_config
from networking_calico.compat import cfg
from networking_calico.compat import log
from networking_calico import etcdv3


LOG = log.getLogger(__name__)


# The node hostname is used as the default identity for leader election
_hostname = socket.gethostname()

# Elector configuration;
elector_opt = cfg.StrOpt(
    'elector_name', default=_hostname,
    help="A unique name to identify this node in leader election"
)

# Register Calico related configuration options
calico_config.register_options(cfg.CONF, additional_options=[elector_opt])


ETCD_DELETE_ACTIONS = set(["delete", "expire", "compareAndDelete"])


class RestartElection(Exception):
    """Exception indicating that we should start our leader election over."""
    pass


class Elector(object):
    def __init__(self, server_id, election_key,
                 old_key=None, interval=30, ttl=60):
        """Class that manages elections.

        :param server_id: Server ID. Must be unique to this server, and should
                          take a value that is meaningful in logs (e.g.
                          hostname)
        :param election_key: The etcd key used for the election - e.g.
                             "/calico/v2/no-region/election"
        :param old_key: A legacy key that does not determine the election, but
                        that we write whenever we write the election_key - e.g.
                             "/calico/v1/election"
                        This makes sense when old_key used to be election_key,
                        and there are other copies of this code running that
                        still need to be upgraded to use the new election key.
                        Our writing of the old key will prevent those not-yet-
                        upgraded copies from thinking that they should win the
                        election.
        :param interval: Interval (seconds) between checks on etcd. Must be > 0
        :param ttl: Time to live (seconds) for etcd values. Must be > interval.
        """
        self._server_id = server_id
        self._key = election_key
        self._old_key = old_key
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
            value, mod_revision = etcdv3.get(self._key)
            mod_revision = int(mod_revision)
        except etcdv3.KeyNotFound:
            LOG.debug("Try to become the master - key not found")
            self._become_master()
            assert False, "_become_master() should not return."
        except Etcd3Exception as e:
            # Something bad and unexpected. Log and reconnect.
            self._log_exception("read current master", e)
            return

        LOG.debug("ID of elected master is : %s", value)
        if value:
            # If we happen to be on the same server, check if the master
            # process is still alive.
            self._check_master_process(value)

        while not self._stopped:
            # We know another instance is the master. Wait until something
            # changes, giving long enough that it really should do (i.e. we
            # expect this read always to return, never to time out).
            #
            # There are small windows where an etcd compaction can occur in
            # between (a) this code being aware of what it thinks is a current
            # DB revision and (b) this code starting a watch from that
            # revision.  Those windows are (1) between the etcdv3.get above and
            # the following etcdv3.watch_once, and (2) between learning a new
            # mod_revision from a watch event and then calling
            # etcdv3.watch_once again.  If there is a compaction in one of
            # those windows, the next watch request will be invalid, and the
            # effect is that etcdv3.watch_once won't report any events, and
            # will raise WatchTimedOut after self._interval * 2 seconds (which
            # is 20s).  That exception will be handled by the Etcd3Exception
            # case below, which means we jump out to _run and then loop round
            # and back into _vote again, rereading the current revision and so
            # ensuring that the next watch will be good.
            try:
                event = etcdv3.watch_once(self._key,
                                          timeout=self._interval * 2,
                                          start_revision=mod_revision + 1)
                LOG.debug("election event: %s", event)
                action = event.get('type', 'SET').lower()
                value = event['kv'].get('value')
                mod_revision = int(event['kv'].get('mod_revision', '0'))
            except etcdv3.KeyNotFound:
                # It should be impossible for somebody to delete the object
                # without us getting the delete action, but safer to handle it.
                LOG.warning("Implausible vanished key - become master")
                self._become_master()
            except Etcd3Exception as e:
                # Something bad and unexpected. Log and reconnect.
                self._log_exception("wait for master change", e)
                return
            LOG.debug("Election key action: %s; new value %s", action, value)
            if (action in ETCD_DELETE_ACTIONS or value is None):
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
            LOG.warning("Unable to parse master ID: %r.", master_id)
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
                LOG.warning("Master was on this server but cannot find its "
                            "PID in /proc.  Removing stale election key.")
                try:
                    deleted = etcdv3.delete(self._key,
                                            existing_value=master_id)
                except Etcd3Exception as e:
                    self._log_exception("remove stale key from dead master", e)
                    deleted = False

                if not deleted:
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
            ttl_lease = etcdv3.get_lease(self._ttl)
            self._master = etcdv3.put(self._key,
                                      self.id_string,
                                      lease=ttl_lease,
                                      mod_revision='0')
        except Exception as e:
            # We could be smarter about what exceptions we allow, but any kind
            # of error means we should give up, and safer to have a broad
            # except here. Log and reconnect.
            self._log_exception("become master", e)
            self._master = False

        if not self._master:
            LOG.info("Race: someone else beat us to be master")
            raise RestartElection()

        LOG.info("Successfully become master - key %s, value %s",
                 self._key, self.id_string)

        # If there's a legacy election key, try to write that now too.
        self._write_old_key(ttl_lease)

        try:
            while not self._stopped:
                try:
                    LOG.debug("Refreshing master role")
                    # Refresh the lease.
                    ttl = ttl_lease.refresh()
                    # Also rewrite the key, so that non-masters see an event on
                    # the key.
                    if not etcdv3.put(self._key,
                                      self.id_string,
                                      lease=ttl_lease,
                                      existing_value=self.id_string):
                        LOG.warning("Key changed or deleted; restart election")
                        raise RestartElection()
                    LOG.debug("Refreshed master role, TTL now is %d", ttl)
                except RestartElection:
                    raise
                except Exception as e:
                    # This is a pretty broad except statement, but anything
                    # going wrong means this instance gives up being the
                    # master.
                    self._log_exception("refresh master role", e)
                    raise RestartElection()

                # If there's a legacy election key, try to write that now too.
                self._write_old_key(ttl_lease)

                eventlet.sleep(self._interval)
        finally:
            LOG.info("Exiting master refresh loop, no longer the master")
            self._master = False
        raise RestartElection()

    def _write_old_key(self, lease):
        # If there's a legacy election key, try to write that now too.
        # Don't worry if there's a problem, as we only do this to
        # assist during an upgrade.
        try:
            if self._old_key:
                etcdv3.put(self._old_key, self.id_string, lease=lease)
        except Exception as e:
            self._log_exception("write old key", e)

    def _log_exception(self, failed_to, exc):
        """Log out an exception we got from a call to etcd.

        :param failed_to: Snippet to include, such as "become master".
        """
        if isinstance(exc, Etcd3Exception):
            # Expected errors (with good messages): timeouts and connection
            # failures.  Don't log stack traces to avoid cluttering the log.
            LOG.warning("Failed to %s - key %s: %r:\n%s", failed_to,
                        self._key, exc, exc.detail_text)
        else:
            # Genuinely unexpected errors.
            LOG.exception("Failed to %s - key %s: %r", failed_to,
                          self._key, exc)

    @property
    def id_string(self):
        return "%s:%d" % (self._server_id, os.getpid())

    def _attempt_step_down(self):
        self._master = False
        try:
            etcdv3.delete(self._key, existing_value=self.id_string)
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


class ElectorStopped(greenlet.GreenletExit):
    """ElectorStopped

    Custom exception used to stop our Elector.  Used to distinguish our
    kill() call from any other potential GreenletExit exception.
    """
    pass
