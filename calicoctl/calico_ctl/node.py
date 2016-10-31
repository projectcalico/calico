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
import os
import signal
import sys

import docker
import docker.errors
import docker.utils
from netaddr import IPAddress, AddrFormatError
from prettytable import PrettyTable
from pycalico.datastore import (ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT,
                                ETCD_KEY_FILE_ENV, ETCD_CERT_FILE_ENV,
                                ETCD_CA_CERT_FILE_ENV, ETCD_SCHEME_ENV,
                                ETCD_SCHEME_DEFAULT, ETCD_ENDPOINTS_ENV)
from pycalico.datastore_datatypes import BGPPeer
from pycalico.datastore_errors import DataStoreError
from pycalico.netns import remove_veth
from pycalico.util import validate_asn, validate_ip
from subprocess32 import call

from checksystem import check_system
from connectors import client, docker_client
from utils import (REQUIRED_MODULES, running_in_container, enforce_root,
                   get_container_ipv_from_arguments, hostname, print_paragraph,
                   convert_asn_to_asplain,
                   ipv6_enabled)

__doc__ = """
Usage:
  calicoctl node [--ip=<IP>] [--ip6=<IP6>] [--node-image=<DOCKER_IMAGE_NAME>]
    [--runtime=<RUNTIME>] [--as=<AS_NUM>] [--log-dir=<LOG_DIR>]
    [--detach=<DETACH>] [--no-pull]
    [(--libnetwork [--libnetwork-image=<LIBNETWORK_IMAGE_NAME>])]
    [--backend=(bird | gobgp | none)]
  calicoctl node stop [--force]
  calicoctl node remove [--hostname=<HOSTNAME>] [--remove-endpoints]
  calicoctl node show
  calicoctl node bgp peer add <PEER_IP> as <AS_NUM>
  calicoctl node bgp peer remove <PEER_IP>
  calicoctl node bgp peer show [--ipv4 | --ipv6]

Description:
  Configure the Calico node containers as well as default BGP information
  for this node.

Options:
  --as=<AS_NUM>             The default AS number for this node.
  --detach=<DETACH>         Set "true" to run Calico service as detached,
                            "false" to run in the foreground.  When using
                            libnetwork, this may not be set to "false".
                            When using --runtime=rkt, --detach is always false.
                            [default: true]
  --force                   Forcefully stop the Calico node
  --hostname=<HOSTNAME>     The hostname from which to remove the Calico node.
  --ip=<IP>                 The local management address to use.
  --ip6=<IP6>               The local IPv6 management address to use.
  --ipv4                    Show IPv4 information only.
  --ipv6                    Show IPv6 information only.
  --libnetwork              (Deprecated) Use the libnetwork plugin.
  --libnetwork-image=<LIBNETWORK_IMAGE_NAME>    (Deprecated) This flag will be ignored.
                            [default: calico/node-libnetwork:latest]
  --log-dir=<LOG_DIR>       The directory for logs [default: /var/log/calico]
  --no-pull                 Prevent from pulling the Calico node Docker images.
  --node-image=<DOCKER_IMAGE_NAME>    Docker image to use for Calico's per-node
                            container. [default: calico/node:latest]
  --remove-endpoints        Remove the endpoint data when deleting the node
                            from the Calico network.
  --runtime=<RUNTIME>       Specify how Calico services should be
                            launched.  When set to "docker" or "rkt", services
                            will be launched via the calico-node container,
                            whereas a value of "none" will not launch them at
                            all. [default: docker]
  --backend=<BACKEND>       Specify which networking backend to use.
                            Choices are "bird", "gobgp" or "none".
                            When set to "none", Calico node run in policy
                            only mode.
"""

CALICO_NETWORKING_ENV = "CALICO_NETWORKING"
CALICO_NETWORKING_DEFAULT = "true"


NO_DEFAULT_POOLS_ENV = "NO_DEFAULT_POOLS"

ETCD_KEY_NODE_FILE = "/etc/calico/certs/key.pem"
ETCD_CERT_NODE_FILE = "/etc/calico/certs/cert.crt"
ETCD_CA_CERT_NODE_FILE = "/etc/calico/certs/ca_cert.crt"

def validate_arguments(arguments):
    """
    Validate argument values:
        <IP>
        <IP6>
        <PEER_IP>
        <AS_NUM>
        <DETACH>

    Arguments not validated:
        <DOCKER_IMAGE_NAME>
        <LOG_DIR>

    :param arguments: Docopt processed arguments
    """
    # Validate IPs
    ip_ok = arguments.get("--ip") is None or \
            arguments.get("--ip") is "" or \
            validate_ip(arguments.get("--ip"), 4)
    ip6_ok = arguments.get("--ip6") is None or \
             arguments.get("--ip6") is "" or \
             validate_ip(arguments.get("--ip6"), 6)
    container_ip_ok = arguments.get("<IP>") is None or \
                      validate_ip(arguments["<IP>"], 4) or \
                      validate_ip(arguments["<IP>"], 6)
    peer_ip_ok = arguments.get("<PEER_IP>") is None or \
                 validate_ip(arguments["<PEER_IP>"], 4) or \
                 validate_ip(arguments["<PEER_IP>"], 6)
    runtime_ok = arguments.get("--runtime") in [None, "none", "docker", "rkt"]

    asnum_ok = True
    asnum = arguments.get("<AS_NUM>") or arguments.get("--as")
    if asnum:
        asnum_ok = validate_asn(asnum)

    detach_ok = True
    if arguments.get("<DETACH>") or arguments.get("--detach"):
        detach_ok = arguments.get("--detach") in ["true", "false"]

    detach_libnetwork_ok = (arguments.get("--detach") == "true" or
                            not arguments.get("--libnetwork"))

    # Print error message
    if not ip_ok:
        print "Invalid IPv4 address specified with --ip argument."
    if not ip6_ok:
        print "Invalid IPv6 address specified with --ip6 argument."
    if not container_ip_ok or not peer_ip_ok:
        print "Invalid IP address specified."
    if not asnum_ok:
        print "Invalid AS Number specified."
    if not detach_ok:
        print "Valid values for --detach are 'true' and 'false'"
    if not detach_libnetwork_ok:
        print "The only valid value for --detach is 'true' when using libnetwork"
    if not runtime_ok:
        print "Runtime must be 'docker', 'rkt' or 'none'."

    # Exit if not valid argument
    if not (ip_ok and ip6_ok and container_ip_ok and peer_ip_ok and asnum_ok
            and detach_ok and detach_libnetwork_ok and runtime_ok):
        sys.exit(1)


def get_networking_backend(docopt_backend):
    """
    Weighs both the deprecated CALICO_NETWORKING_ENV and the new --backend from docopt to determine
    which backend should be used. Ideally, we could use the docopt [default: bird], but until we've
    finished deprecating CALICO_NETWORKING_ENV, we need to be able to consider every combination of the
    two variables.

    :param docopt_backend: The docopt value for --backend. Should be "bird", "gobgp", "none", or None (if
    they are using CALICO_NETWORKING_ENV instead).
    :return:
    """
    # If backend was specified via docopt, use it, as command line args take precedence over ENV vars.
    if docopt_backend != None:
        return docopt_backend
    else:
        # Otherwise, check if they are using the old binary flag: CALICO_NETWORK_ENV
        calico_networking = os.getenv(CALICO_NETWORKING_ENV)
        if not calico_networking:
            # Neither environment variable nor command line passed, use default: bird.
            return "bird"
        else:
            print >> sys.stderr, "WARNING: %s will be deprecated: use '--backend' instead" \
                                 % (CALICO_NETWORKING_ENV)
            if calico_networking == "false":
                # environment variable passed to disable Bird. use: none
                return "none"
            else:
                # environment variable passed as assumed default. use: bird.
                return "bird"


def node(arguments):
    """
    Main dispatcher for node commands. Calls the corresponding helper function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    validate_arguments(arguments)

    backend = get_networking_backend(arguments.get('--backend'))

    as_num = convert_asn_to_asplain(arguments.get("<AS_NUM>") or arguments.get("--as"))

    if arguments.get("bgp"):
        if arguments.get("peer"):
            ip_version = get_container_ipv_from_arguments(arguments)
            if arguments.get("add"):
                node_bgppeer_add(arguments.get("<PEER_IP>"), ip_version,
                                 as_num)
            elif arguments.get("remove"):
                node_bgppeer_remove(arguments.get("<PEER_IP>"), ip_version)
            elif arguments.get("show"):
                if not ip_version:
                    node_bgppeer_show(4)
                    node_bgppeer_show(6)
                else:
                    node_bgppeer_show(ip_version)
    elif arguments.get("stop"):
        node_stop(arguments.get("--force"))
    elif arguments.get("remove"):
        node_remove(arguments.get("--remove-endpoints"),
                    arguments.get("--hostname"))
    elif arguments.get("show"):
        node_show()
    else:
        assert arguments.get("--detach") in ["true", "false"]
        detach = arguments.get("--detach") == "true"

        # Set libnetwork_enabled to False if --libnetwork flag is not passed 
        libnetwork_enabled = False if not arguments.get("--libnetwork") else True

        node_start(ip=arguments.get("--ip"),
                   node_image=arguments.get('--node-image'),
                   runtime=arguments.get("--runtime"),
                   log_dir=arguments.get("--log-dir"),
                   ip6=arguments.get("--ip6"),
                   as_num=as_num,
                   detach=detach,
                   libnetwork_enabled=libnetwork_enabled,
                   no_pull=arguments.get("--no-pull"),
                   backend=backend)


def node_start(node_image, runtime, log_dir, ip, ip6, as_num, detach,
               libnetwork_enabled, no_pull, backend):
    """
    Create the calico-node container and establish Calico networking on this
    host.

    :param ip:  The IPv4 address of the host.
    :param node_image:  The calico-node image to use.
    :param ip6:  The IPv6 address of the host (or None if not configured)
    :param as_num:  The BGP AS Number to use for this node.  If not specified
    the global default value will be used.
    :param detach: True to run in Docker's "detached" mode, False to run
    attached.
    :param libnetwork_enabled: True to run libnetwork plugin inside calico-node.
    :param no_pull: Boolean, True to prevent function from pulling the Calico
    node Docker images.
    :param backend: String, backend choice. Should be "bird", "none", or "gobgp".
    :return:  None.
    """
    # The command has to be run as root to access iptables and services
    enforce_root()

    # Normally, Felix will load the modules it needs, but when running inside a
    # container it might not be able to do so. Ensure the required modules are
    # loaded each time the node starts.
    # We only make a best effort attempt because the command may fail if the
    # modules are built in.
    # We'll warn during the check_system() if the modules are unavailable.
    if not running_in_container():
        try:
            call(["modprobe", "-a"] + REQUIRED_MODULES)
        except OSError:
            pass

        _setup_ip_forwarding()
        _set_nf_conntrack_max()

        # Print warnings for any known system issues before continuing
        if runtime == 'docker' and not running_in_container():
            using_docker = True
        else:
            using_docker = False

        (_, docker_ok, etcd_ok) = \
            check_system(quit_if_error=False, libnetwork=libnetwork_enabled,
                         check_docker=using_docker,
                         check_modules=not running_in_container())

        if not etcd_ok or (using_docker and not docker_ok):
            sys.exit(1)

    # Ensure log directory and /var/run/calico exist so that they can be
    # mounted into the containers.
    try:
        os.makedirs(log_dir)
    except OSError:
        pass
    try:
        os.makedirs("/var/run/calico")
    except OSError:
        pass

    # The format of the authority and endpoints strings have already been
    # validated.
    etcd_authority = os.getenv(ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT)
    etcd_endpoints = os.getenv(ETCD_ENDPOINTS_ENV)

    # Get etcd SSL environment variables if they exist
    etcd_scheme = os.getenv(ETCD_SCHEME_ENV, ETCD_SCHEME_DEFAULT)
    etcd_key_file = os.getenv(ETCD_KEY_FILE_ENV)
    etcd_cert_file = os.getenv(ETCD_CERT_FILE_ENV)
    etcd_ca_cert_file = os.getenv(ETCD_CA_CERT_FILE_ENV)

    etcd_volumes = []
    etcd_binds = {}
    etcd_envs = ["ETCD_AUTHORITY=%s" % etcd_authority,
                 "ETCD_SCHEME=%s" % etcd_scheme]

    if etcd_endpoints:
        etcd_envs.append("ETCD_ENDPOINTS=%s" % etcd_endpoints)

    if etcd_ca_cert_file:
        etcd_volumes.append(ETCD_CA_CERT_NODE_FILE)
        etcd_binds[etcd_ca_cert_file] = {"bind": ETCD_CA_CERT_NODE_FILE,
                                         "ro": True}
        etcd_envs.append("ETCD_CA_CERT_FILE=%s" % ETCD_CA_CERT_NODE_FILE)

    if etcd_key_file and etcd_cert_file:
        etcd_volumes.append(ETCD_KEY_NODE_FILE)
        etcd_binds[etcd_key_file] = {"bind": ETCD_KEY_NODE_FILE,
                                     "ro": True}
        etcd_envs.append("ETCD_KEY_FILE=%s" % ETCD_KEY_NODE_FILE)

        etcd_volumes.append(ETCD_CERT_NODE_FILE)
        etcd_binds[etcd_cert_file] = {"bind": ETCD_CERT_NODE_FILE,
                                      "ro": True}
        etcd_envs.append("ETCD_CERT_FILE=%s" % ETCD_CERT_NODE_FILE)

    if runtime == 'docker':
        _start_node_container_docker(ip, ip6, as_num, log_dir, node_image, detach,
                                     etcd_envs, etcd_volumes, etcd_binds, libnetwork_enabled, no_pull, backend)

    if runtime == 'rkt':
        _start_node_container_rkt(ip, ip6, as_num, node_image, etcd_envs,
                                  etcd_volumes, etcd_binds, backend)


def _start_node_container_docker(ip, ip6, as_num, log_dir, node_image, detach, etcd_envs,
                                 etcd_volumes, etcd_binds, libnetwork_enabled, no_pull, backend):
    """
    Start the main Calico node container.

    :param ip:  The IPv4 address of the host.
    :param ip6:  The IPv6 address of the host (or None if not configured)
    :param as_num: The AS number for the host
    :param log_dir:  The log directory to use.
    :param libnetwork_enabled: True to run libnetwork plugin inside calico-node.
    :param detach: True to run in Docker's "detached" mode, False to run
    attached.
    :param etcd_envs: Etcd environment variables to pass into the container
    :param etcd_volumes: List of mount_paths for etcd files to mount on the
    container
    :param etcd_binds: Dictionary of host file and mount file pairs for etcd
    files to mount on the container
    :param no_pull: Boolean, True to prevent function from pulling the Calico
    node Docker image.
    :return: None.
    """
    no_default_pools = os.getenv(NO_DEFAULT_POOLS_ENV)

    if not no_pull:
        # Make sure the required image is pulled before removing the old one.
        # This minimizes downtime during upgrade.
        _find_or_pull_node_image(node_image)

    try:
        docker_client.remove_container("calico-node", force=True)
    except docker.errors.APIError as err:
        if err.response.status_code != 404:
            raise

    # This is to convert libnetwork_enabled (bool) into a string to pass it as an ENV var value
    if libnetwork_enabled:
       libnetwork_flag_str = "true"
    else:
       libnetwork_flag_str = "false"

    environment = [
        "HOSTNAME=%s" % hostname,
        "IP=%s" % (ip or ""),
        "IP6=%s" % (ip6 or ""),
        "CALICO_NETWORKING_BACKEND=%s" % backend,
        "AS=%s" % (as_num or ""),
        "NO_DEFAULT_POOLS=%s" % (no_default_pools or ""),
        "CALICO_LIBNETWORK_ENABLED=%s" % libnetwork_flag_str
    ] + etcd_envs

    binds = {
        log_dir:
            {
                "bind": "/var/log/calico",
                "ro": False
            },
        "/var/run/calico":
            {
                "bind": "/var/run/calico",
                "ro": False
            },
        "/lib/modules":
            {
                "bind": "/lib/modules",
                "ro": False
            }
    }

    # Additional rw binds (/run/docker/plugins and /var/run/docker.sock) necessary when libnetwork is enabled
    if libnetwork_enabled:
        binds["/run/docker/plugins"] = {
            "bind": "/run/docker/plugins",
            "ro": False
            }

        binds["/var/run/docker.sock"] = {
            "bind": "/var/run/docker.sock",
            "ro": False
        }

    binds.update(etcd_binds)

    host_config = docker_client.create_host_config(
        privileged=True,
        restart_policy={"Name": "always"},
        network_mode="host",
        binds=binds)

    volumes = ["/var/log/calico", "/var/run/calico", "/lib/modules"] + etcd_volumes

    # Add /run/docker/plugins to the list of volumes to be mounted when libnetwork is enabled
    if libnetwork_enabled:
        volumes.append("/run/docker/plugins")
        volumes.append("/var/run/docker.sock")

    container = docker_client.create_container(
        node_image,
        name="calico-node",
        detach=True,
        environment=environment,
        host_config=host_config,
        volumes=volumes)
    cid = container["Id"]

    env_string = ""
    for an_env in environment:
        env_string += " -e " + an_env

    vol_string = ""
    for a_vol in binds:
        vol_string += " -v %s:%s" % (a_vol, binds[a_vol]["bind"])

    detach_string = " -d" if detach else ""

    print "Running Docker container with the following command:\n"
    print "docker run%s --restart=always --net=host --privileged --name=calico-node%s%s %s\n" % \
          (detach_string, env_string, vol_string, node_image)
    docker_client.start(container)
    print "Calico node is running with id: %s" % cid

    # Print a message to indicate libnetwork plugin is running when libnetwork is enabled
    if libnetwork_enabled:
        print "Calico node running with libnetwork plugin enabled"

    print "Waiting for successful startup"
    _attach_and_stream(container, detach)

def _start_node_container_rkt(ip, ip6, as_num, node_image, etcd_envs,
                              etcd_volumes, etcd_binds, backend):
    """
    Start the main Calico node container using rkt

    :param ip:  The IPv4 address of the host.
    :param ip6:  The IPv6 address of the host (or None if not configured)
    :param as_num: The AS number for the host.
    :param node_image:  The calico-node image to use.
    :param etcd_envs: Etcd environment variables to pass into the container
    :param etcd_volumes: List of mount_paths for etcd files to mount on the
    container
    :param etcd_binds: Dictionary of host file and mount file pairs for etcd
    files to mount on the container
    :param backend:
    :return: None.
    """
    if node_image == "calico/node:latest":
        # The default image is being used so convert to the rkt format.
        node_image = "registry-1.docker.io/calico/node:latest"

    no_default_pools = os.getenv(NO_DEFAULT_POOLS_ENV)

    environment = [
        "CALICO_DISABLE_FILE_LOGGING=true",
        "HOSTNAME=%s" % hostname,
        "IP=%s" % (ip or ""),
        "IP6=%s" % (ip6 or ""),
        "CALICO_NETWORKING_BACKEND=%s" % backend,
        "AS=%s" % (as_num or ""),
        "NO_DEFAULT_POOLS=%s" % (no_default_pools or "")
    ] + etcd_envs

    # TODO No support for SSL (etcd binds) yet

    env_commands = []
    for env_var in environment:
        env_commands += ["--set-env=%s" % (env_var)]

    # Maybe in future we'll want to have a configurable path for the
    # stage1-fly.aci but for now use the following algorithm
    # 1) If there is a file in the current directory, use that.
    # 2) Otherwise use the file from the default location.
    #
    # This allows the image to be overridden (e.g. if using a custom version of
    # rkt on CoreOS where the default file can't be updated)
    stage1_filename = "stage1-fly.aci"
    if os.path.isfile(stage1_filename):
        stage1_path = stage1_filename
    else:
        stage1_path = "/usr/share/rkt/stage1-fly.aci"

    rkt_command = ["systemd-run", "--unit=calico-node", "rkt", "run",
                   "--stage1-path=%s" % stage1_path,
                   "--insecure-options=image",
                   "--volume=birdctl,kind=host,source=/var/run/calico,readOnly=false",
                   "--mount", "volume=birdctl,target=/var/run/calico",
                   "--volume=modules,kind=host,source=/lib/modules,readOnly=false",
                   "--mount", "volume=modules,target=/lib/modules"
                   ] + \
                  env_commands + \
                  [node_image]

    print " ".join(rkt_command)
    call(rkt_command)

def _setup_ip_forwarding():
    """
    Ensure that IP forwarding is enabled.
    :return: None
    """
    # Enable IP forwarding since all compute hosts are vRouters.
    # IPv4 forwarding should be enabled already by docker.
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write("1")
    except Exception:
        print "ERROR: Could not enable ipv4 forwarding."
        sys.exit(1)

    try:
        if ipv6_enabled():
            with open('/proc/sys/net/ipv6/conf/all/forwarding', 'w') as f:
                f.write("1")
    except Exception:
        print "ERROR: Could not enable ipv6 forwarding."
        sys.exit(1)

def _set_nf_conntrack_max():
    """
    A common problem on Linux systems is running out of space in the conntrack
    table, which can cause poor iptables performance. This can happen if you
    run a lot of workloads on a given host, or if your workloads create a lot
    of TCP connections or bidirectional UDP streams.

    To avoid this becoming a problem, we recommend increasing the conntrack
    table size. To do so, run the following commands:
    """
    try:
        with open('/proc/sys/net/netfilter/nf_conntrack_max', 'w') as f:
            f.write("1000000")
    except Exception:
        print "WARNING: Could not set nf_contrack_max. This may have an impact at scale."
        print "See http://docs.projectcalico.org/en/latest/configuration.html#system-configuration for more details"

def node_stop(force):
    """
    Stop the Calico node.  This stops the containers (calico/node and
    calico/node-libnetwork) that are started by calicoctl node.
    """
    # The command has to be run as root to stop the calico-node service
    enforce_root()

    endpoints = len(client.get_endpoints(hostname=hostname))
    if endpoints:
        if not force:
            print_paragraph("Current host has active endpoints so can't be "
                "stopped.  Force with --force")
            print_paragraph("Note that stopping the node while there are "
                            "active endpoints may make it difficult to clean "
                            "up the endpoints: for example, Docker containers "
                            "networked using libnetwork with Calico will not "
                            "invoke network cleanup during the normal "
                            "container lifecycle.")
            sys.exit(1)
        else:
            print_paragraph("Stopping node while host has active endpoints.  "
                            "If this in error, restart the node using the "
                            "'calicoctl node' command.")

    try:
        docker_client.stop("calico-node")
    except docker.errors.APIError as err:
        if err.response.status_code != 404:
            raise
    try:
        docker_client.stop("calico-libnetwork")
    except docker.errors.APIError as err:
        if err.response.status_code != 404:
            raise
    try:
        call(["systemctl", "stop", "calico-node.service"])
    except OSError:
        # systemctl not installed, ignore error.
        pass

    print "Node stopped"


def node_remove(remove_endpoints, host):
    """
    Remove a node from the Calico network.
    :param remove_endpoints: Whether the endpoint data should be forcibly
    removed.
    :param host: The hostname of the host whose node will be removed, or None if
    removing this host's node.
    :return: None.
    """
    host_to_remove = host or hostname

    if host_to_remove == hostname and (_container_running("calico-node") or
                                       _container_running("calico-libnetwork")):
        print_paragraph("The node cannot be removed while it is running.  "
                        "Please run 'calicoctl node stop' to stop the node "
                        "before removing it.")
        sys.exit(1)

    endpoints = client.get_endpoints(hostname=host_to_remove)
    if endpoints and not remove_endpoints:
        print_paragraph("The node has active Calico endpoints so can't be "
                        "deleted. Force with --remove-endpoints")
        print_paragraph("Note that forcible removing the node may leave some "
                        "workloads in an indeterminate networked state.  If "
                        "this is in error, you may restart the node using the "
                        "'calicoctl node' command and clean up the workloads "
                        "in the normal way.")
        sys.exit(1)

    # Remove the veths, and release all IPs associated with the endpoints.  To
    # release the IPs, we construct a set of all IP addresses across all
    # endpoints (this assumes the endpoint nets are all single IPs).
    ips = set()
    for endpoint in endpoints:
        remove_veth(endpoint.name)
        ips |= {net.ip for net in endpoint.ipv4_nets}
        ips |= {net.ip for net in endpoint.ipv6_nets}
    client.release_ips(ips)

    # Remove the IPAM host data.
    client.remove_ipam_host(host_to_remove)

    # If the host had an IPIP tunnel address, release it back to the IPAM pool
    # so that we don't leak it when we delete the config.
    raw_addr = client.get_per_host_config(host_to_remove, "IpInIpTunnelAddr")
    try:
        ip_addr = IPAddress(raw_addr)
        client.release_ips({ip_addr})
    except (AddrFormatError, ValueError, TypeError):
        pass

    client.remove_per_host_config(host_to_remove, "IpInIpTunnelAddr")
    client.remove_host(host_to_remove)

    print "Node configuration removed"


def _container_running(container_name):
    """
    Check if a container is currently running or not.
    :param container_name:  The container name or ID.
    :return: True if running, otherwise False.
    """
    try:
        cdata = docker_client.inspect_container(container_name)
    except docker.errors.APIError as err:
        if err.response.status_code != 404:
            raise
        return False
    else:
        return cdata["State"]["Running"]


def node_show():
    """
    Show hostname and node information for each node in the Calico cluster.
    """
    # Set up output table
    headings = ["Hostname",
                "Bird IPv4",
                "Bird IPv6",
                "AS Num",
                "BGP Peers v4",
                "BGP Peers v6"]
    x = PrettyTable(headings, sortby="Hostname")

    try:
        # Get dictionary of host data, indexed by hostname
        hosts = client.get_hosts_data_dict()
        for (host, data) in hosts.iteritems():

            # Combine BGP peer IP and AS numbers into single values
            peer_v4_list = [peer["ip"] + " as " + peer["as_num"]
                            for peer in data["peer_v4"]]
            peer_v6_list = [peer["ip"] + " as " + peer["as_num"]
                            for peer in data["peer_v6"]]

            if data["as_num"]:
                bgp_as = data["as_num"]
            else:
                bgp_as = client.get_default_node_as()
                bgp_as += " (inherited)"
            x.add_row([host,
                       data["ip_addr_v4"],
                       data["ip_addr_v6"],
                       bgp_as,
                       "\n".join(peer_v4_list),
                       "\n".join(peer_v6_list)])
    except DataStoreError:
        print "Error connecting to etcd."
        sys.exit(1)

    print str(x) + "\n"


def node_bgppeer_add(ip, version, as_num):
    """
    Add a new BGP peer with the supplied IP address and AS Number to this node.

    :param ip: The address to add
    :param version: 4 or 6
    :param as_num: The peer AS Number.
    :return: None
    """
    address = IPAddress(ip)
    peer = BGPPeer(address, as_num)
    client.add_bgp_peer(version, peer, hostname=hostname)


def node_bgppeer_remove(ip, version):
    """
    Remove a global BGP peer from this node.

    :param ip: The address to use.
    :param version: 4 or 6
    :return: None
    """
    address = IPAddress(ip)
    try:
        client.remove_bgp_peer(version, address, hostname=hostname)
    except KeyError:
        print "%s is not a configured peer for this node." % address
        sys.exit(1)
    else:
        print "BGP peer removed from node configuration"


def node_bgppeer_show(version):
    """
    Print a list of the BGP Peers for this node.
    """
    assert version in (4, 6)
    peers = client.get_bgp_peers(version, hostname=hostname)
    if peers:
        heading = "Node specific IPv%s BGP Peer" % version
        x = PrettyTable([heading, "AS Num"], sortby=heading)
        for peer in peers:
            x.add_row([peer.ip, peer.as_num])
        x.align = "l"
        print x.get_string(sortby=heading)
    else:
        print "No IPv%s BGP Peers defined for this node.\n" % version


def _find_or_pull_node_image(image_name):
    """
    Check if Docker has a cached copy of an image, and if not, attempt to pull
    it.

    :param image_name: The full name of the image.
    :return: None.
    """
    try:
        _ = docker_client.inspect_image(image_name)
    except docker.errors.APIError as err:
        if err.response.status_code == 404:
            # TODO: Display proper status bar
            print_paragraph("Pulling Docker image %s" % image_name)

            try:
                # Pull the image and then verify that it was succesfully
                # pulled (the pull doesn't raise an exception on failure).
                docker_client.pull(image_name)
                docker_client.inspect_image(image_name)
            except docker.errors.APIError:
                # Unable to download the Docker image.
                print_paragraph("ERROR: Unable to download Docker image.")
                print_paragraph("Please verify that you have network "
                                "connectivity to DockerHub and that, if you "
                                "explicitly specified which calico/node image "
                                "to use, the image name is correct.")
                sys.exit(1)


def _attach_and_stream(container, startup_only):
    """
    Attach to a container and stream its stdout and stderr output to this
    process's stdout.  If the user presses Ctrl-C or the process is killed,
    also stop the Docker container.

    If startup_only is set, then only attach until the container starts up successfully.

    :param container: Docker container to attach to.
    :return: None.
    """

    # Register a SIGTERM handler, so we shut down the container if this
    # process is kill'd.
    def handle_sigterm(sig, frame):
        print "Got SIGTERM"
        docker_client.stop(container)
        sys.exit(0)
    signal.signal(signal.SIGTERM, handle_sigterm)
    stop_container_on_exit = True
    exit_code = 1

    output = docker_client.attach(container, stream=True)
    line_buf = ""
    try:
        for raw_data in output:
            sys.stdout.write(raw_data)
            if startup_only:
                # We've been asked to exit after the container has started,
                # look for the successful startup message.  We buffer one line
                # of output in case we get a split line from the output stream.
                line_buf += raw_data
                if "Calico node started successfully" in line_buf:
                    stop_container_on_exit = False
                    break
                line_buf = line_buf.rsplit('\n')[-1]
    except KeyboardInterrupt:
        # Mainline. Someone pressed Ctrl-C.
        print "Stopping Calico node..."
        stop_container_on_exit = True
        exit_code = 130
    finally:
        # Could either be this process is being killed, or output generator
        # raises an exception.
        if stop_container_on_exit:
            docker_client.stop(container)
            # If the container is stopped, some sort of error occurred.
            sys.exit(exit_code)
