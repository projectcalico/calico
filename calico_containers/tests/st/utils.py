import sh
from sh import docker
import socket


def get_ip():
    """Return a string of the IP of the hosts eth0 interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def cleanup_inside(name):
    """
    Clean the inside of a container by deleting the containers and images within it.
    """
    docker("exec", "-t", name, "bash", "-c",
           "docker rm -f $(docker ps -qa) ; docker rmi $(docker images -qa)",
           _ok_code=[0, 1, 255])  # 255 is; "bash": executable file not found in $PATH


def delete_container(name):
    """
    Cleanly delete a container.
    """
    # We *must* remove all inner containers and images before removing the outer
    # container. Otherwise the inner images will stick around and fill disk.
    # https://github.com/jpetazzo/dind#important-warning-about-disk-usage
    cleanup_inside(name)
    sh.docker.rm("-f", name, _ok_code=[0, 1])
