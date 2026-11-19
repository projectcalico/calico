# -*- coding: utf-8 -*-
# Copyright (c) 2015-2026 Tigera, Inc. All rights reserved.
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
calicotest.common.ssh
~~~~~~~~~~~~~~~

Contains an SSH helper class used to execute commands and perform file
transfer on a remote host, and other SSH related utilities.
"""
from collections import namedtuple
import logging
import socket
import time

import paramiko

from calicotest.common.testutils import retry_until_success

_log = logging.getLogger(__name__)

SSHResult = namedtuple("SSHResult", ["return_code", "stdout", "stderr"])


class SSH(object):
    """
    An SSH connector allowing execution of commands and file transfer.

    :param fqdn: The FQDN of the host.
    :param username: The username to use to access the host.
    :param password: The password to use to authenticate to the host.
    """

    def __init__(self, fqdn, username, password, keyfile=None, desc=None):
        self.fqdn = str(fqdn)
        self.username = username
        self.password = password
        self._ssh = None
        self._rebooted = False
        self.keyfile = keyfile
        self.retries = 3
        self.desc = desc

        _log.debug("Creating ssh object %s", self)

        # Since this can be a context manager, we only disconnect if the
        # current context manager opened the connection.
        self.context_count = 0

    def connect(self):
        """
        Connect an SSH client to the node.
        """
        _log.debug("Entered ssh.connect() for %s", self)
        # If connected then do nothing.
        if self._ssh and not self._rebooted:
            _log.debug("ssh appears to be connected - do nothing")
            return

        # FIXME: This loop is to get around the fact that Paramiko only waits
        # 15 seconds for the SSH banner, but snapshot restored VMs may take
        # longer.
        last_exception = None
        retries = self.retries
        while retries:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                _log.debug(
                    "Attempting to connect to %s@%s, pw=%s, key=%s",
                    self.username,
                    self.fqdn,
                    self.password,
                    self.keyfile,
                )
                ssh.connect(
                    self.fqdn,
                    username=self.username,
                    password=self.password,
                    timeout=10,
                    key_filename=self.keyfile,
                )
                self._ssh = ssh
                self._rebooted = False
                break
            except paramiko.ssh_exception.SSHException as e:
                last_exception = e
                if "Error reading SSH protocol banner" not in str(e):
                    _log.warn("SSH into %s: %r", self.fqdn, e)
                    raise
                else:
                    _log.info(
                        "Hit expected paramiko error, retrying. Retries left %s",
                        retries,
                    )
                    retries -= 1
            except socket.error as e:
                last_exception = e
                _log.info(
                    "Failed to ssh to %s, retries remaining: %s (%r)",
                    self.fqdn,
                    retries,
                    e,
                )
                retries -= 1
                time.sleep(15)
            except Exception as e:
                last_exception = e
                _log.warn("Hit exception sshing into %s:\n%s", self.fqdn, e)
                raise
        else:
            raise RuntimeError(
                "Failed to SSH into %s (%s):\n%s"
                % (self.fqdn, self.desc, last_exception)
            )

    def disconnect(self):
        """
        Disconnect the SSH connection to the node.
        """
        _log.debug("Entered ssh.disconnect for %s", self)
        if self._ssh:
            try:
                self._ssh.close()
            except Exception:
                _log.exception("Error disconnecting SSH session")
            self._ssh = None
            self._rebooted = False

    def execute(self, command):
        """
        Execute a command on the host over SSH.  The SSH helper should already
        be connected.

        :param command: The command to execute
        :return: Tuple of (status, stdout, stderr)
        """
        _log.debug("Entered ssh.execute with %s:", command)
        self._check_connected()
        return self._execute(command)

    def _execute(self, command):
        """
        Internal method to execute a command.  This does not reconnect if a
        reboot has occurred - and will therefore throw an exception if no
        longer connected.

        :param command: The command to execute
        :return: Tuple of (status, stdout, stderr)
        """
        _log.info("Running command on %s", self)
        _log.info("  - Command: %s", command)
        stdin, stdout, stderr = self._ssh.exec_command(command)
        # We need to eat all of stdout and stderr to avoid hanging the host.
        out = stdout.read()
        err = stderr.read()
        status = stdout.channel.recv_exit_status()

        out_utf8 = out.decode("utf-8")
        err_utf8 = err.decode("utf-8")

        # Trace out the results
        _log.info("- return: %s", status)
        _log.info("- stdout -\n%s", out_utf8)
        _log.info("- stderr -\n%s", err_utf8)

        return SSHResult(status, out_utf8, err_utf8)

    def execute_readline(self, command):
        """
        Execute a command and return individual lines as a generator.
        Raises an exception if the return code is non-zero.  Stderr is ignored.

        Use this rather than execute if the command outputs a large amount of
        data that cannot be handled as a single string.

        :return: Generator of individual lines.
        """
        self._check_connected()
        _log.debug("Running command on %s", self)
        _log.debug("  - Command: %s", command)
        stdin, stdout, stderr = self._ssh.exec_command(command)

        try:
            # Read and return one line at a time until no more data is
            # returned.
            while True:
                line = stdout.readline()
                if not line:
                    break
                yield line
        finally:
            # We need to eat all of stdout and stderr to avoid hanging the
            # host.
            stdout.read()
            err = stderr.read()
            status = stdout.channel.recv_exit_status()
            _log.debug("- return: %s", status)
            _log.debug("- stderr -\n%s", err)

        if status:
            raise Exception(
                "Command %s returned non-zero exit code %s" % (command, status)
            )

    def send_file(self, local_name, remote_name):
        """
        Send a file to the host using SFTP.  The SSH helper should already be
        connected.

        :param local_name: The local name of the file.
        :param remote_name: The remote name for the file.
        """
        _log.info("send file: %s", local_name)
        self._check_connected()
        ftp = self._ssh.open_sftp()
        try:
            ftp.put(local_name, remote_name)
        finally:
            ftp.close()

    def get_file(self, remote_name, local_name):
        """
        Retrieve the file from the remote node.  The SSH helper should already
        be connected.

        :param remote_name: The remote file name
        :param local_name: The local file name
        """
        self._check_connected()
        ftp = self._ssh.open_sftp()
        try:
            ftp.get(remote_name, local_name)
        finally:
            ftp.close()

    def reboot(self, wait_for_restart=False):
        """
        Issue a sudo reboot to the host.  It assumes the host has passwordless
        sudo access, and that this SSH helper is already connected.

        :param wait_for_restart: Wait for the server to restart
        """
        self._check_connected()
        self.execute("sudo reboot")

        # Sleep to ensure the reboot has actually happened.
        time.sleep(5)

        # Invoke the common restarted handling.
        self.restarted(wait_for_restart=wait_for_restart)

    def restarted(self, wait_for_restart=False):
        """
        Invoke this if the VM was restarted through an external process and
        thus requiring the SSH to reconnect.

        :param wait_for_restart:  Wait for the server to restart
        """
        _log.debug("Entered restarted() for %s", self)
        self._rebooted = True

        if wait_for_restart:
            _log.debug("Waiting for restart")
            # Attempt to reconnect
            retry_until_success(
                self.connect, retries=10, wait_time=10, context_string="SSH.restarted"
            )

    @property
    def still_connected(self):
        """
        Check if the current SSH session underpinning this object is still
        connected.  This can be used to check if a reboot really has occurred
        when expected and that the SSH session has actually dropped.

        :return: True if connected, False otherwise.  Asserts if the SSH object
        was never explicitly connected.
        """
        assert self._ssh, "SSH was never connected"
        try:
            self._execute("echo hello")
            return True
        except paramiko.ssh_exception.SSHException:
            return False
        except socket.error:
            return False

    def assert_connection_dead(self):
        """
        Assert that the current SSH connection is dead.
        """
        assert not self.still_connected, "SSH session is still active"

    def _check_connected(self):
        """
        Assert that this helper is connected, and if previously restarted
        reconnect.
        """
        _log.debug("Entered _check_connected")
        assert self._ssh, "SSH is not connected"

        # If previously restarted and not reconnected since, then
        # reconnect now.
        if self._rebooted:
            _log.debug("self._rebooted = True, so reconnecting")
            self.connect()

    def __repr__(self):
        if self.desc:
            return "SSH(%s %s)" % (self.fqdn, self.desc)
        return "SSH(%s)" % self.fqdn

    def __str__(self):
        return self.__repr__()

    # These two methods implement the Context Manager protocol.  Note that we
    # need to be careful that someone may have connected outside a context
    # manager.
    def __enter__(self):
        if not self._ssh or self.context_count:
            self.context_count += 1
            self.connect()
        return self

    def __exit__(self, *args):
        if self.context_count:
            self.context_count -= 1
            if not self.context_count:
                self.disconnect()
        return False  # Never swallow exceptions.
