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
  calicoctl checksystem [--fix] [--libnetwork]

Description:
  Check for incompatibilities between calico and the host system

Options:
  --fix  Deprecated: checksystem no longer fixes issues that it detects
  --libnetwork  Check for the correct docker version for libnetwork deployments
"""
import sys
import re
import sh

import docker
from requests import ConnectionError
from subprocess32 import check_output

from utils import DOCKER_VERSION, DOCKER_LIBNETWORK_VERSION, REQUIRED_MODULES
from utils import enforce_root
from connectors import docker_client


def checksystem(arguments):
    """
    Main dispatcher for checksystem commands. Calls the corresponding helper
    function. checksystem only has one main function, so we call that function
    directly.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    if arguments["--fix"]:
        print >> sys.stderr, "WARNING: Deprecated flag --fix:" \
                             "checksystem no longer fixes detected issues"
    check_system(quit_if_error=True,
                 libnetwork=arguments["--libnetwork"])

def check_system(quit_if_error=False, libnetwork=False):
    """
    Checks that the system is setup correctly.

    :param quit_if_error: if True, quit with error code 1 if any issues are
    detected.
    :param libnetwork: If True, check for Docker version >= v1.21 to support libnetwork
    :return: True if all system dependencies are in the proper state, False if
    they are not. This function will sys.exit(1) instead of returning false if
    quit_if_error == True
    """
    modules_ok = _check_modules()
    docker_ok = _check_docker_version(libnetwork)

    system_ok = modules_ok and docker_ok

    if quit_if_error and not system_ok:
        sys.exit(1)

    return system_ok


def modules_available(modules):
    """
    Checks if the specified modules are available.

    :param modules: A list of of module names to check
    :return: True if all the module is available, False if not.
    """
    # For the modules we're expecting to look for, the mainline case is that
    # they will be loadable modules. Therefore, loadable modules are checked
    # first and builtins are checked only if needed.
    kernel_version = check_output(["uname", "-r"]).rstrip()
    modules_loadable_path = "/lib/modules/%s/modules.dep" % kernel_version
    available_lines = open(modules_loadable_path).readlines()
    all_available = check_module_lines(available_lines, modules)

    if not all_available:
        modules_builtin_path = "/lib/modules/%s/modules.builtin" % kernel_version
        builtin_lines = open(modules_builtin_path).readlines()
        all_available = check_module_lines(builtin_lines, modules)

    return all_available


def check_module_lines(lines, modules):
    """
    Check if a normalized module name appears in the given lines
    :param lines: THe lines to check
    :param modules: A list of module names - e.g. ["xt_set", "ip6_tables"]
    :return: True if the module appears. False otherwise
    """
    all_present = True
    for module in modules:
        full_module = "/%s.ko" % module
        all_present= any(full_module in s for s in lines)
        if not all_present:
            break
    return all_present


def normalize_version(version):
    """
    This function convers a string representation of a version into
    a list of integer values.
    e.g.:   "1.5.10" => [1, 5, 10]
    http://stackoverflow.com/questions/1714027/version-number-comparison
    """
    return [int(x) for x in re.sub(r'(\.0+)*$', '', version).split(".")]


def _check_modules():
    """
    Check system kernel modules
    :return: True if kernel modules are ok.
    """
    system_ok = True

    for module in REQUIRED_MODULES:
        # Check modules individually to get a better error message
        if not modules_available([module]):
            print >> sys.stderr, "WARNING: Unable to detect the %s " \
                                 "module." % module
            system_ok = False
    return system_ok


def _check_docker_version(libnetwork=False):
    """
    Check the Docker version is supported.
    :param libnetwork: If True, check for Docker version >= v1.21 to support libnetwork
    :return: True if Docker version is OK.
    """
    system_ok = True

    # Set correct docker version
    version = DOCKER_VERSION if not libnetwork else DOCKER_LIBNETWORK_VERSION

    # Check docker version compatability
    try:
        info = docker_client.version()
    except ConnectionError:
        print >> sys.stderr, "ERROR: Docker daemon not running."
        system_ok = False
    except docker.errors.APIError:
        print >> sys.stderr, "ERROR: Docker server must support Docker " \
                             "Remote API v%s or greater." % version
        system_ok = False
    else:
        api_version = normalize_version(info['ApiVersion'])
        # Check that API Version is above the minimum supported version
        if cmp(api_version, normalize_version(version)) < 0:
            if libnetwork:
                print >> sys.stderr, "ERROR: Docker Version does not support Libnetwork."

            print >> sys.stderr, "ERROR: Docker server must support Docker " \
                                 "Remote API v%s or greater." % version
            system_ok = False

    return system_ok
