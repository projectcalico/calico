import os
import sh
from sh import docker


def setup_package():
    """
    Sets up docker images and host containers for running the STs.
    """
    # Pull and save each image, so we can use them inside the host containers.
    print sh.bash("./build_node.sh").stdout
    docker.save("--output", "calico_containers/calico-node.tar", "calico/node")
    if not os.path.isfile("busybox.tar"):
        docker.pull("busybox:latest")
        docker.save("--output", "calico_containers/busybox.tar", "busybox:latest")

    # Create the calicoctl binary here so it will be in the volume mounted on the hosts.
    print sh.bash("./create_binary.sh")


def teardown_package():
    pass
