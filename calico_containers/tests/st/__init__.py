import os
import sh
from sh import docker

BUILD_ENV = "CALICO_BUILD"

def do_build():
    """Returns whether we should build the node and calicoctl binaries."""
    try:
        build = os.environ[BUILD_ENV]
        return build.lower() not in ["no", "n", "f", "false"]
    except KeyError:
        return True


def setup_package():
    """
    Sets up docker images and host containers for running the STs.
    """
    # Pull and save each image, so we can use them inside the host containers.
    if not do_build():
        print "Using pre-build calicoctl and calico-node images"
        return

    print sh.bash("./build_node.sh").stdout
    docker.save("--output", "calico_containers/calico-node.tar", "calico/node")
    if not os.path.isfile("calico_containers/busybox.tar"):
        docker.pull("busybox:latest")
        docker.save("--output", "calico_containers/busybox.tar", "busybox:latest")

    # Create the calicoctl binary here so it will be in the volume mounted on the hosts.
    print sh.bash("./create_binary.sh")


def teardown_package():
    pass
