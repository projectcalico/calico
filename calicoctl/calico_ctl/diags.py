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
Usage:
  calicoctl diags [--log-dir=<LOG_DIR>]

Description:
  Save diagnostic information

Options:
  --log-dir=<LOG_DIR>  The directory for logs [default: /var/log/calico]
"""
import sys
import os
from datetime import datetime
import tarfile
import tempfile
import traceback
import subprocess

import re
from etcd import EtcdException
from pycalico.datastore import DatastoreClient
from shutil import copytree, ignore_patterns

from utils import print_paragraph, enforce_root


def diags(arguments):
    """
    Main dispatcher for diags commands. Calls the corresponding helper function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    # The command has to be run as root for ipset collections (and iptables)
    enforce_root()
    print("Collecting diagnostics")
    save_diags(arguments["--log-dir"])
    sys.exit(0)

temp_diags_dir = None

def save_diags(log_dir):
    # Create temp directory
    temp_dir = tempfile.mkdtemp()
    global temp_diags_dir
    temp_diags_dir = os.path.join(temp_dir, 'diagnostics')
    os.mkdir(temp_diags_dir)
    print("Using temp dir: %s" % temp_dir)

    write_diags(None, "date")
    write_diags(None, "hostname")
    write_diags("Dumping netstat", "netstat --all --numeric")
    write_diags("Dumping routes (IPv4)", "ip -4 route")
    write_diags("Dumping routes (IPv6)", "ip -6 route")
    write_diags("Dumping interface info (IPv4)", "ip -4 addr")
    write_diags("Dumping interface info (IPv6)", "ip -6 addr")
    write_diags("Dumping iptables (IPv4)", "iptables-save")
    write_diags("Dumping iptables (IPv6)", "ip6tables-save")
    # Sometimes the host doesn't have ipset installed, or it's the wrong version;
    # so fall back to running it inside the calico/node container.
    write_diags("Dumping ipsets", "ipset list || docker run --privileged --net=host -it calico/node ipset list")
    # If running under rkt, get the journal for the calico/node container.
    write_diags("Copying journal for calico-node.service", "journalctl -u calico-node.service --no-pager")

    # Ask Felix to dump stats to its log file - ignore errors as the
    # calico/node container might not be running.  Gathering of the logs is
    # dependent on environment.
    print("Dumping felix stats")
    subprocess.call(["pkill", "-SIGUSR1", "felix"])

    # Otherwise, calico logs are in the log directory.
    if os.path.isdir(log_dir):
        print("Copying Calico logs")
        # Skip the lock files as they can only be copied by root.
        copytree(log_dir, os.path.join(temp_diags_dir, "logs"),
                 ignore=ignore_patterns('lock'))
    else:
        print('No logs found in %s; skipping log copying' % log_dir)

    # Dump the contents of the etcd datastore.
    print("Dumping datastore")
    with DiagsErrorWriter(temp_diags_dir, 'etcd_calico') as f:
        try:
            datastore_client = DatastoreClient()
            datastore_data = datastore_client.etcd_client.read("/calico",
                                                               recursive=True)
            f.write("dir?, key, value\n")
            # TODO: python-etcd bug: Leaves show up twice in get_subtree().
            for child in datastore_data.get_subtree():
                if child.dir:
                    f.write("DIR,  %s,\n" % child.key)
                else:
                    f.write("FILE, %s, %s\n" % (child.key, child.value))
        except EtcdException, e:
            print "Unable to dump etcd datastore"
            f.write("Unable to dump etcd datastore: %s" % e)

    # Create tar.
    tar_filename = datetime.strftime(datetime.today(),
                                     "diags-%d%m%y_%H%M%S.tar.gz")
    full_tar_path = os.path.join(temp_dir, tar_filename)
    with tarfile.open(full_tar_path, "w:gz") as tar:
        # pass in arcname, otherwise zip contains layers of subfolders
        tar.add(temp_dir, arcname="")

    print("\nDiags saved to %s\n" % (full_tar_path))
    print_paragraph("If required, you can upload the diagnostics bundle to a "
                    "file sharing service such as transfer.sh using curl or "
                    "similar.  For example:")
    print("  curl --upload-file %s https://transfer.sh/%s" %
             (full_tar_path, os.path.basename(full_tar_path)))


def write_diags(comment, command):
    if comment:
        print comment

    # Sanitize the filename.
    filename = command
    filename = re.sub(r'\s*\|\|.*', "", filename)  # Strip out any optional (||) clauses
    filename = re.sub(r'[^a-zA-Z0-9 -]', "", filename)  # Strip out non letters and numbers
    filename = re.sub(r'\s', "_", filename)  # Substitute underscore for spaces

    with DiagsErrorWriter(temp_diags_dir, filename) as f:
        try:
            output = subprocess.check_output(command,
                                             shell=True,
                                             stderr=subprocess.STDOUT)
            f.write(output)
        except subprocess.CalledProcessError as e:
            print "Problem running command: %s\n  %s" % (command, e.output)
            f.write("Problem running command: %s\n\n" % command)
            f.write("%s\n" % e.output)


class DiagsErrorWriter(object):
    """
    Context manager used to handle error handling when writing diagnostics.
    In the event of an exception being thrown within the context manager, the
    details of the exception are written to file and the exception is
    swallowed.  This allows the diagnostics to retrieve as much information as
    possible.
    """

    def __init__(self, temp_dir, filename):
        self.temp_dir = temp_dir
        self.filename = filename
        self.file = None

    def __enter__(self):
        """
        Open the diags file for writing, and return the file object.
        :return: The file object.
        """
        self.file = open(os.path.join(self.temp_dir, self.filename), "w")
        return self.file

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Close the diagnostics file and if an error occurred, write that into
        the file.
        :param exc_type: The exception type, or None.
        :param exc_val: The exception instance, or None.
        :param exc_tb: The exception traceback, or None.
        :return: False for KeyboardInterrupt exceptions, or no exceptions,
                 True for all other exceptions (exception is traced in file).
        """
        if exc_type is KeyboardInterrupt:
            rc = False
        elif exc_type is None:
            rc = False
        else:
            print "  - Error gathering diagnostics"
            self.file.write("\nError gathering diagnostics\n")
            self.file.write("Exception: %s(%s)\n" % (exc_type, exc_val))
            traceback.print_tb(exc_tb, None, self.file)
            rc = True

        self.file.close()
        return rc
