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

    host1_exec("while ! docker ps; do sleep 1; done && "
               "docker load --input /code/calico-node.tar && "
               "docker load --input /code/busybox.tar && "
               "docker load --input /code/nsenter.tar && "
               "docker load --input /code/etcd.tar")

    host2_exec("while ! docker ps; do sleep 1; done && "
               "docker load --input /code/calico-node.tar && "
               "docker load --input /code/busybox.tar && "
               "docker load --input /code/nsenter.tar")

    host1_ip = docker.inspect("--format", "'{{ .NetworkSettings.IPAddress }}'", "host1").stdout.rstrip()

    cmd = ("--name calico "
          "--advertise-client-urls http://%s:2379 "
          "--listen-client-urls http://0.0.0.0:2379 "
          "--initial-advertise-peer-urls http://%s:2380 "
          "--listen-peer-urls http://0.0.0.0:2380 "
          "--initial-cluster-token etcd-cluster-2 "
          "--initial-cluster calico=http://%s:2380 "
          "--initial-cluster-state new" % (host1_ip, host1_ip, host1_ip))
    host1_exec('docker run -d -p 2379:2379 quay.io/coreos/etcd:v2.0.10 %s' % cmd)


def teardown_package():
    pass
