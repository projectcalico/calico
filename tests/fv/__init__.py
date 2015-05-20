import os
import sh
from sh import docker
from docker_host import DockerHost

def setup_package():
    """
    Sets up docker images and host containers for running the STs.
    """
    # We *must* remove all inner containers and images before removing the outer
    # container. Otherwise the inner images will stick around and fill disk.
    # https://github.com/jpetazzo/dind#important-warning-about-disk-usage
    containers = docker.ps("-qa").split()
    for container in containers:
        docker("exec", "-t", container, "bash", "-c",
               "docker rm -f $(docker ps -qa) ; docker rmi $(docker images -qa)", _ok_code=[0, 1])
    print "Containers and images within host containers removed."

    sh.docker.rm("-f", *containers, _ok_code=[0, 1])
    print "Host containers removed."

    # Pull and save each image, so we can use them inside the host containers.
    print sh.bash("./build_node.sh").stdout
    docker.save("--output", "calico-node.tar", "calico/node")
    if not os.path.isfile("busybox.tar"):
        docker.pull("busybox:latest")
        docker.save("--output", "busybox.tar", "busybox:latest")
    if not os.path.isfile("nsenter.tar"):
        docker.pull("jpetazzo/nsenter:latest")
        docker.save("--output", "nsenter.tar", "jpetazzo/nsenter:latest")
    if not os.path.isfile("etcd.tar"):
        docker.pull("quay.io/coreos/etcd:v2.0.10")
        docker.save("--output", "etcd.tar", "quay.io/coreos/etcd:v2.0.10")

    # Create the calicoctl binary here so it will be in the volume mounted on the hosts.
    print sh.bash("./create_binary.sh")
    print "Calicoctl binary created."

    DockerHost('')

def teardown_package():
    pass
