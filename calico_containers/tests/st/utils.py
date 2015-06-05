import sh
from sh import docker
import socket
from time import sleep


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
           _ok_code=[0,
                     1,  # Caused by 'docker: "rm" requires a minimum of 1 argument.' et al.
                     127,  # Caused by '"docker": no command found'
                     255,  # Caused by '"bash": executable file not found in $PATH'
                    ]
          )


def delete_container(name):
    """
    Cleanly delete a container.
    """
    # We *must* remove all inner containers and images before removing the outer
    # container. Otherwise the inner images will stick around and fill disk.
    # https://github.com/jpetazzo/dind#important-warning-about-disk-usage
    cleanup_inside(name)
    sh.docker.rm("-f", name, _ok_code=[0, 1])


def retry_until_success(function, retries=10, ex_class=Exception):
    """
    Retries function until no exception is thrown. If exception continues,
    it is reraised.

    :param function: the function to be repeatedly called
    :param retries: the maximum number of times to retry the function.
    A value of 0 will run the function once with no retries.
    :param ex_class: The class of expected exceptions.
    :returns: the value returned by function
    """
    for retry in range(retries + 1):
        try:
            result = function()
        except ex_class:
            if retry < retries:
                sleep(1)
            else:
                raise
        else:
            # Successfully ran the function
            return result
