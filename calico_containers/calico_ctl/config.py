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
  calicoctl config felix <NAME> [<VALUE>|--remove] [--force]
  calicoctl config bgp <NAME> [<VALUE>|--remove] [--force]
  calicoctl config node bgp <NAME> [<VALUE>|--remove] [--force]

Description:
  Configure or show low-level component configuration for Felix and BGP.

Options:
 --remove  Remove the configuration entry.
 --force   Force update of configuration entry even if key value is unknown,
           or the value is not recognized as valid.

Valid configuration:
  Command         | <NAME>   | <VALUE>s
------------------+----------+-----------------------------------------
  config felix    | loglevel | none debug info warning error critical
  config bgp      | loglevel | none debug info
  config node bgp | loglevel | none debug info

Warnings:
  -  Changing the global BGP logging levels using the `calicoctl config bgp`
     command may cause all BGP sessions to bounce potentially resulting in a
     transient loss of service.  If you need to change the logging level for
     BGP, it is recommended to change the levels on a per-node basis using
     the `calicoctl config node bgp` command.
"""
import re
import sys

from etcd import EtcdKeyNotFound
from pycalico.datastore import handle_errors
from pycalico.datastore import CONFIG_PATH, BGP_HOST_PATH, BGP_GLOBAL_PATH

from connectors import client
from utils import print_paragraph
from utils import hostname

# Dictionaries providing look up between the configuration name, and a tuple
# of (internal name, value regex string)
FELIX_CONFIG_DATA = {
    "loglevel": ("LogSeverityScreen", "none|debug|info|warning|error|critical")
}
BGP_CONFIG_DATA = {
    "loglevel": ("loglevel", "none|debug|info")
}

def validate_arguments(arguments):
    """
    Validate argument values:
        <NAME>
        <VALUE>

    :param arguments: Docopt processed arguments
    """
    config_data = _get_config_data(arguments)
    name = arguments["<NAME>"]
    if name not in config_data:
        print_paragraph("The configuration '%s' is not recognized as a "
                        "valid option." % name)
        if arguments["--force"]:
            print_paragraph("The --force option is set.")
            return
        else:
            print_paragraph("Use the --force option to override.")
            sys.exit(1)

    value = arguments.get("<VALUE>")
    if value:
        _, valid_values = config_data[name]
        valid_values_re = re.compile(valid_values)
        if not valid_values_re.match(value):
            print_paragraph("The configuration value '%s' is not recognized "
                            "as a valid value." % value)
            if arguments["--force"]:
                print_paragraph("The --force option is set.")
                return
            else:
                print_paragraph("Use the --force option to override.")
                sys.exit(1)


def config(arguments):
    """
    Main dispatcher for config commands. Calls the corresponding helper
    function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    validate_arguments(arguments)

    key = _get_key(arguments)
    value = arguments.get("<VALUE>")

    if arguments["--remove"]:
        _remove_config(key)
    elif value:
        _set_config(key, value)
    else:
        _show_config(key)


def _get_key(arguments):
    """
    Determine the config key based on the arguments.
    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: The datastore path for the config key.
    """
    # Get the base path.
    if arguments.get("felix"):
        base = CONFIG_PATH
    elif arguments.get("node"):
        base = BGP_HOST_PATH % {"hostname": hostname}
    else:
        base = BGP_GLOBAL_PATH

    # Determine the actual name of the field.  Look this up from the config
    # data, otherwise just use the name.
    config_data = _get_config_data(arguments)
    name = arguments["<NAME>"]
    if name in config_data:
        name, _ = config_data[name]

    return base + name


def _get_config_data(arguments):
    """
    Return the config data for the supplied arguments.
    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: A dictionary providing look up between the configuration names
    and a tuple of (internal name, value regex string)
    """
    if arguments.get("felix"):
        config_data = FELIX_CONFIG_DATA
    else:
        config_data = BGP_CONFIG_DATA
    return config_data


@handle_errors
def _remove_config(key):
    """
    Remove the configuration value in the datastore.
    :param path:  The configuration key.
    """
    try:
        client.etcd_client.delete(key)
    except EtcdKeyNotFound:
        print "No value configured"
    else:
        print "Value removed"


@handle_errors
def _set_config(key, value):
    """
    Set the configuration in the datastore.
    :param path:  The configuration key.
    """
    client.etcd_client.write(key, value)


@handle_errors
def _show_config(key):
    """
    Show the configuration currently stored in the datastore.
    :param key: The configuration key.
    """
    try:
        value = client.etcd_client.read(key).value
    except EtcdKeyNotFound:
        value = "No value configured"
    print value