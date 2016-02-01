# Copyright 2015 Metaswitch Networks
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
  calicoctl diags [--log-dir=<LOG_DIR>] [--runtime=<RUNTIME>]

Description:
  Save diagnostic information

Options:
  --log-dir=<LOG_DIR>  The directory for logs [default: /var/log/calico]
  --runtime=<RUNTIME>  Specify the runtime used to run the calico/node 
                       container, either "docker" or "rkt". 
                       [default: docker]
"""
import sys
import sh
import os
from datetime import datetime
import tarfile
import socket
import tempfile
import traceback
import subprocess

from etcd import EtcdException
from pycalico.datastore import DatastoreClient
from shutil import copytree, ignore_patterns

from utils import hostname
from utils import print_paragraph


def diags(arguments):
    """
    Main dispatcher for diags commands. Calls the corresponding helper function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    print("Collecting diags")

    # Check runtime.  
    runtime = arguments.get("--runtime")
    if not runtime in ["docker", "rkt"]:
        print "Invalid runtime specified: '%s'" % runtime
        sys.exit(1)

    save_diags(arguments["--log-dir"], runtime)
    sys.exit(0)


def save_diags(log_dir, runtime="docker"):
    # Create temp directory
    temp_dir = tempfile.mkdtemp()
    temp_diags_dir = os.path.join(temp_dir, 'diagnostics')
    os.mkdir(temp_diags_dir)
    print("Using temp dir: %s" % temp_dir)

    # Write date to file
    with DiagsErrorWriter(temp_diags_dir, 'date') as f:
        f.write("DATE=%s" % datetime.strftime(datetime.today(),
                                              "%Y-%m-%d_%H-%M-%S"))

    # Write hostname to file
    with DiagsErrorWriter(temp_diags_dir, 'hostname') as f:
        f.write(str(hostname))

    # Write netstat output to file
    with DiagsErrorWriter(temp_diags_dir, 'netstat') as f:
        try:
            print("Dumping netstat output")
            netstat = sh.Command._create("netstat")

            f.writelines(netstat(
                # Display all sockets (default: connected)
                all=True,
                # Don't resolve names
                numeric=True))

        except sh.CommandNotFound as e:
            print "  - Missing command: %s" % e.message
            f.writelines("Missing command: %s\n" % e.message)

    # Write routes
    print("Dumping routes")
    with DiagsErrorWriter(temp_diags_dir, 'route') as f:
        try:
            route = sh.Command._create("route")
            f.write("route --numeric\n")
            f.writelines(route(numeric=True))
            f.write('\n')
        except sh.CommandNotFound as e:
            print "  - Missing command: %s" % e.message
            f.writelines("Missing command: %s\n" % e.message)

        try:
            ip = sh.Command._create("ip")
            f.write("ip route\n")
            f.writelines(ip("route"))
            f.write('\n')

            f.write("ip -6 route\n")
            f.writelines(ip("-6", "route"))
            f.write('\n')
        except sh.CommandNotFound as e:
            print "  - Missing command: %s" % e.message
            f.writelines("Missing command: %s\n" % e.message)

    # Dump iptables
    with DiagsErrorWriter(temp_diags_dir, 'iptables') as f:
        try:
            iptables_save = sh.Command._create("iptables-save")
            print("Dumping iptables")
            f.writelines(iptables_save())
        except sh.CommandNotFound as e:
            print "  - Missing command: %s" % e.message
            f.writelines("Missing command: %s\n" % e.message)

    # Dump ipset list
    # TODO: ipset might not be installed on the host. But we don't want to
    # gather the diags in the container because it might not be running...
    with DiagsErrorWriter(temp_diags_dir, 'ipset') as f:
        try:
            ipset = sh.Command._create("ipset")
            print("Dumping ipset")
            f.writelines(ipset("list"))
        except sh.CommandNotFound as e:
            print "  - Missing command: %s" % e.message
            f.writelines("Missing command: %s\n" % e.message)
        except sh.ErrorReturnCode_1 as e:
            print "  - Error running ipset. Maybe you need to run as root."
            f.writelines("Error running ipset: %s\n" % e)

    # Ask Felix to dump stats to its log file - ignore errors as the
    # calico/node container might not be running.
    subprocess.call(["pkill", "-SIGUSR1", "felix"])

    # If running under rkt, get the journal for the calico/node container.
    print "Copying journal for calico-node.service"
    f = open(temp_diags_dir + "/calico-node.journal", "w")
    try:
        journal = subprocess.check_output(["journalctl", "-u", 
                                           "calico-node.service", 
                                           "--no-pager"])
    except OSError:
        print "Unable to copy journal"
    else:
        f.write(journal)
    finally:
        f.close()

    if os.path.isdir(log_dir):
        print("Copying Calico logs")
        # Skip the lock files as they can only be copied by root.
        copytree(log_dir, os.path.join(temp_diags_dir, "logs"),
                 ignore=ignore_patterns('lock'))
    else:
        print('No logs found in %s; skipping log copying' % log_dir)

    print("Dumping datastore")
    # TODO: May want to move this into datastore.py as a dump-calico function
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
