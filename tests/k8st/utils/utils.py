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

import datetime
import functools
import json
import logging
import random
import string
import subprocess
import time

_log = logging.getLogger(__name__)


# Helps with printing diags after a test.
class DiagsCollector(object):
    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_value, traceback):
        # Print out diagnostics for the test. These will go to screen
        # on test failure.
        _log.info("===================================================")
        _log.info("============= COLLECTING DIAGS FOR TEST ===========")
        _log.info("===================================================")
        kubectl("get deployments,pods,svc,endpoints --all-namespaces -o wide")
        for resource in ["node", "bgpconfig", "bgppeer", "gnp", "felixconfig"]:
            _log.info("")
            calicoctl("get " + resource + " -o yaml")
        for node in ["kube-master", "kube-node-1", "kube-node-2"]:
            _log.info("")
            run("docker exec " + node + " ip r")
        kubectl("logs -n kube-system -l k8s-app=calico-node")
        _log.info("===================================================")
        _log.info("============= COLLECTED DIAGS FOR TEST ============")
        _log.info("===================================================")


def start_external_node_with_bgp(name, config):
    # Check how much disk space we have.
    run("df -h")

    # Setup external node: use privileged mode for setting routes
    run("docker run -d "
        "--privileged "
        "--name %s "
        "--network kubeadm-dind-net "
        "mirantis/kubeadm-dind-cluster:v1.10" % name)

    # Check how much space there is inside the container.  We may need
    # to retry this, as it may take a while for the image to download
    # and the container to start running.
    while True:
        try:
            run("docker exec %s df -h" % name)
            break
        except subprocess.CalledProcessError:
            _log.exception("Container not ready yet")
            time.sleep(20)

    # Install bird on extra node
    run("docker exec %s apt update" % name)
    run("docker exec %s apt install -y bird" % name)
    run("docker exec %s mkdir /run/bird" % name)
    with open('bird.conf', 'w') as birdconfig:
        birdconfig.write(config)
    run("docker cp bird.conf %s:/etc/bird/bird.conf" % name)
    run("rm bird.conf")
    run("docker exec %s service bird restart" % name)


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


def run(command, logerr=True, allow_fail=False):
    out = ""
    _log.info("[%s] %s", datetime.datetime.now(), command)
    try:
        out = subprocess.check_output(command,
                                      shell=True,
                                      stderr=subprocess.STDOUT)
        _log.info("Output:\n%s", out)
    except subprocess.CalledProcessError as e:
        if logerr:
            _log.exception("Failure output:\n%s", e.output)
        if not allow_fail:
            raise
    return out


def curl(hostname, container="kube-node-extra"):
    cmd = "docker exec %s curl --connect-timeout 2 -m 3 %s" % (container,
                                                               hostname)
    return run(cmd)


def kubectl(args, logerr=True, allow_fail=False):
    return run("kubectl " + args, logerr=logerr, allow_fail=allow_fail)


def calicoctl(args, allow_fail=False):
    return kubectl("exec -i -n kube-system calicoctl -- /calicoctl " + args,
                   allow_fail=allow_fail)


def calicoctl_apply_dict(object_dict):
    calicoctl("""apply -f - << EOF
%s
EOF
""" % json.dumps(object_dict))


def generate_unique_id(length, prefix=""):
    random_string = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))
    return "%s-%s" % (prefix, random_string)
