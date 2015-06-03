from netaddr import IPAddress


class Workload(object):
    def __init__(self, host, name, ip=None, image="busybox", use_powerstrip=True):
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
            args += ["--env", "CALICO_IP=%s" % ip]
        args.append(image)
        command = ' '.join(args)

        host.execute(command, use_powerstrip=use_powerstrip)

        if ip and IPAddress(ip).version == 6:
            version = "GlobalIPv6Address"
        else:
            version = "IPAddress"
        self.ip = host.execute("docker inspect --format "
                               "'{{ .NetworkSettings.%s }}' %s" % (version, name),
                               use_powerstrip=use_powerstrip).stdout.rstrip()
        if ip and ip != 'auto':
            assert ip == self.ip, "IP param = %s, configured IP = %s." % (ip, self.ip)

    def execute(self, command, **kwargs):
        return self.host.execute("docker exec %s %s" % (self.name, command))

    def ping(self, ip):
        version = IPAddress(ip).version
        assert version in [4, 6]
        if version == 4:
            ping = "ping"
        elif version == 6:
            ping = "ping6"

        args = [
            ping,
            "-c", "1",  # Number of pings
            "-W", "2",  # Timeout for each ping
            ip,
        ]
        command = ' '.join(args)
        return self.execute(command)

    def __str__(self):
        return self.name
