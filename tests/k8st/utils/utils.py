# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

import functools
import logging
import subprocess
import time

_log = logging.getLogger(__name__)


def start_external_node_with_bgp(name, config):
    # # Setup external node: use privileged mode for setting routes
    subprocess.check_call("docker run -d "
                          "--privileged "
                          "--name %s "
                          "--network kubeadm-dind-net "
                          "mirantis/kubeadm-dind-cluster:v1.10" % name,
                          shell=True)
    # Install bird on extra node
    subprocess.check_call("docker exec %s apt update" % name, shell=True)
    subprocess.check_call("docker exec %s apt install -y bird" % name, shell=True)
    subprocess.check_call("docker exec %s mkdir /run/bird" % name, shell=True)
    with open('bird.conf', 'w') as birdconfig:
        birdconfig.write(config)
    subprocess.check_call("docker cp bird.conf %s:/etc/bird/bird.conf" % name, shell=True)
    subprocess.check_call("rm bird.conf", shell=True)
    subprocess.check_call("docker exec %s service bird restart" % name, shell=True)


def retry_until_success(fun,
                        retries=10,
                        wait_time=1,
                        ex_class=None,
                        log_exception=True,
                        function_args=None,
                        function_kwargs=None):
    """
    Retries function until no exception is thrown. If exception continues,
    it is reraised.
    :param fun: the function to be repeatedly called
    :param retries: the maximum number of times to retry the function.  A value
    of 0 will run the function once with no retries.
    :param wait_time: the time to wait between retries (in s)
    :param ex_class: The class of expected exceptions.
    :param log_exception: By default this function logs the exception if the
    function is still failing after max retries.   This log can sometimes be
    superfluous -- if e.g. the calling code is going to make a better log --
    and can be suppressed by setting this parameter to False.
    :param function_args: A list of arguments to pass to function
    :param function_kwargs: A dictionary of keyword arguments to pass to
                            function
    :returns: the value returned by function
    """
    if function_args is None:
        function_args = []
    if function_kwargs is None:
        function_kwargs = {}
    for retry in range(retries + 1):
        try:
            result = fun(*function_args, **function_kwargs)
        except Exception as e:
            if ex_class and e.__class__ is not ex_class:
                _log.exception("Hit unexpected exception in function - "
                               "not retrying.")
                raise
            if retry < retries:
                _log.debug("Hit exception in function - retrying: %s", e)
                time.sleep(wait_time)
            else:
                if log_exception:
                    _log.exception("Function %s did not succeed before "
                                   "timeout.", fun)
                raise
        else:
            # Successfully ran the function
            return result


def function_name(f):
    """
    A function that returns the name of the provided function as a string.
    This primarily exists to handle the fact that functools.partial is an
    imperfect wrapper.
    """
    if isinstance(f, functools.partial):
        f = f.func

    try:
        return f.__name__
    except Exception:
        return "<unknown function>"
