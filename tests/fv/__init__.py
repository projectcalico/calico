import os
import sh
from sh import docker


def setup_package():
    pwd = sh.pwd().stdout.rstrip()

    docker_exec = docker.bake("exec")
    host1_exec = docker_exec.bake("-t", "host1", "bash", "-c")
    host2_exec = docker_exec.bake("-t", "host2", "bash", "-c")

    # We *must* remove all inner containers and images before removing the outer
    # container. Otherwise the inner images will stick around and fill disk.
    # https://github.com/jpetazzo/dind#important-warning-about-disk-usage
    try:
        host1_exec('docker rm -f $(docker ps -qa) ; docker rmi $(docker images -qa)')
    except sh.ErrorReturnCode_1:
        pass
    try:
        host2_exec('docker rm -f $(docker ps -qa) ; docker rmi $(docker images -qa)')
    except sh.ErrorReturnCode_1:
        pass
    print "Containers and images within host containers removed."

    try:
        sh.docker.rm("-f", "host1", "host2")
    except sh.ErrorReturnCode:
        pass
    print "Host containers removed."

    # # Save and load each image, so we can use them in the inner host containers.
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

    print sh.bash("./create_binary.sh")

    print docker.run("--privileged", "-v", pwd+":/code", "--name", "host1", "-tid", "jpetazzo/dind")
    docker.run("--privileged", "-v", pwd+":/code", "--name", "host2", "-tid", "jpetazzo/dind")


def teardown_package():
    pass
