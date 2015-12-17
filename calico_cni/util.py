# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import logging
from cloghandler import ConcurrentRotatingFileHandler
from constants import * 
from subprocess32 import check_output


def configure_logging(logger, log_filename, log_level=logging.INFO, log_dir=LOG_DIR):
    """Configures logging for given logger using the given filename.

    :return None.
    """
    # If the logging directory doesn't exist, create it.
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Determine path to log file.
    log_path = os.path.join(log_dir, log_filename)

    # Create an IdentityFilter.
    identity = get_identifier()
    identity_filter = IdentityFilter(identity=identity)

    # Create a log handler and formtter and apply to _log.
    hdlr = ConcurrentRotatingFileHandler(filename=log_path,
                                         maxBytes=1000000,
                                         backupCount=5)
    hdlr.addFilter(identity_filter)
    formatter = logging.Formatter(LOG_FORMAT)
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(log_level)

    # Attach a stderr handler to the log.
    stderr_hdlr = logging.StreamHandler(sys.stderr)
    stderr_hdlr.setLevel(log_level)
    stderr_hdlr.setFormatter(formatter)
    logger.addHandler(stderr_hdlr)


def parse_cni_args(cni_args):
    """Parses the given CNI_ARGS string into key value pairs
    and returns a dictionary containing the arguments.

    e.g "FOO=BAR;ABC=123" -> {"FOO": "BAR", "ABC": "123"}

    :param cni_args
    :return: args_to_return - dictionary of parsed cni args
    """
    # Dictionary to return.
    args_to_return = {}

    _log.debug("Parsing CNI_ARGS: %s", cni_args)
    for k,v in CNI_ARGS_RE.findall(cni_args):
        _log.debug("\tParsed CNI_ARG: %s=%s", k, v)
        args_to_return[k.strip()] = v.strip()
    _log.debug("Parsed CNI_ARGS: %s", args_to_return)
    return args_to_return


def get_identifier():
    """
    Returns an appropriate identifier for use in logging.

    For most orchestrators, this is the container ID.  For Kubernetes,
    this is the pod namespace/name.
    """
    cni_args = parse_cni_args(os.environ.get(CNI_ARGS_ENV, ""))
    if K8S_POD_NAME in cni_args:
        identifier = "%s/%s" % (cni_args.get(K8S_POD_NAMESPACE, "unknown"), 
                                cni_args.get(K8S_POD_NAME, "unknown"))
    else:
        identifier = os.environ.get(CNI_CONTAINERID_ENV, 
                                    "UnknownId")[:8]
    return identifier
    

def _log_interfaces(namespace):
    """
    Log interface state in namespace and default namespace.

    :param namespace
    :type namespace str
    """
    try:
        if _log.isEnabledFor(logging.DEBUG):
            interfaces = check_output(['ip', 'addr'])
            _log.debug("Interfaces in default namespace:\n%s", interfaces)

            namespaces = check_output(['ip', 'netns', 'list'])
            _log.debug("Namespaces:\n%s", namespaces)

            cmd = ['ip', 'netns', 'exec', str(namespace), 'ip', 'addr']
            namespace_interfaces = check_output(cmd)

            _log.debug("Interfaces in namespace %s:\n%s",
                         namespace, namespace_interfaces)
    except BaseException:
        # Don't exit if we hit an error logging out the interfaces.
        _log.exception("Ignoring error logging interfaces")


class IdentityFilter(logging.Filter):
    """
    Filter class to impart contextual identity information onto loggers.
    """
    def __init__(self, identity):
        self.identity = identity

    def filter(self, record):
        record.identity = self.identity
        return True


# Set up logger for util.py
LOG_FILENAME = "cni.log"
_log = logging.getLogger(__name__)
configure_logging(_log, LOG_FILENAME)
