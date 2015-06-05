from netaddr import IPAddress, AddrFormatError


class Workload(object):
    """
    A calico workload.

    These are the end-users containers that will run application-level software.
    """
    def __init__(self, host, name, ip=None, image="busybox", use_powerstrip=True):
        """
        Create the workload and detect its IPs.

        :param host: The host container on which this workload is instantiated.
        All commands executed by this container will be passed through the host
        via docker exec.
        :param name: The name given to the workload container. This name is
        passed to docker and can be used inside docker commands.
        :param ip: The IP to be assigned to this workload via calico. May be
        either IPv4 or IPv6. Calico supports multiple IPs per workload, but
        this testing framework does not yet.
        :param image: The docker image to be used to instantiate this
        container. busybox used by default because it is extremely small and
        has ping.
        :param use_powerstrip: Use Powerstrip in front of docker to inform
        calico of networking changes.
        """
        self.host = host
        self.name = name

        args = [
            "docker", "run",
            "--tty",
            "--interactive",
            "--detach",
            "--name", name,
        ]
        if ip:
            # Powerstrip passes the CALICO_IP var to calico.
            args += ["--env", "CALICO_IP=%s" % ip]
        args.append(image)
        command = ' '.join(args)

        host.execute(command, use_powerstrip=use_powerstrip)

        # There is an unofficial ip=auto option in addition to ip=None.
        try:
            version = IPAddress(ip).version
        except AddrFormatError:
            version = None

        if version == 6:
            version_key = "GlobalIPv6Address"
        else:
            version_key = "IPAddress"

        self.ip = host.execute("docker inspect --format "
                               "'{{ .NetworkSettings.%s }}' %s" % (version_key, name),
                               use_powerstrip=use_powerstrip).stdout.rstrip()
        if ip and ip != 'auto':
            assert ip == self.ip, "IP param = %s, configured IP = %s." % (ip, self.ip)

    def execute(self, command, **kwargs):
        """
        Execute arbitrary commands on this workload.
        """
        return self.host.execute("docker exec %s %s" % (self.name, command))

    def ping(self, ip):
        """
        Execute a ping from this workload to the ip.
        """
        version = IPAddress(ip).version
        assert version in [4, 6]
        if version == 4:
            ping = "ping"
        elif version == 6:
            ping = "ping6"

        args = [
            ping,
            "-c", "1",  # Number of pings
            "-W", "1",  # Timeout for each ping
            ip,
        ]
        command = ' '.join(args)
        return self.execute(command)

    def __str__(self):
        return self.name
