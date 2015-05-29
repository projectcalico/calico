import os
import sh
from sh import docker


def setup_package():
    """
    Sets up docker images and host containers for running the STs.
    """
    # Pull and save each image, so we can use them inside the host containers.
    print sh.bash("./build_node.sh").stdout
    docker.save("--output", "calico-node.tar", "calico/node")
    if not os.path.isfile("busybox.tar"):
        docker.pull("busybox:latest")
        docker.save("--output", "busybox.tar", "busybox:latest")
    if not os.path.isfile("nsenter.tar"):
        docker.pull("jpetazzo/nsenter:latest")
        docker.save("--output", "nsenter.tar", "jpetazzo/nsenter:latest")

    # Create the calicoctl binary here so it will be in the volume mounted on the hosts.
    print sh.bash("./create_binary.sh")


def teardown_package():
    pass
