class Workload(object):
    def __init__(self, host, name, ip=None, image="busybox", use_powerstrip=True):
        self.host = host
        self.name = name
        self.ip = ip

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

    def execute(self, command, **kwargs):
        return self.host.execute("docker exec %s %s" % (self.name, command))

    def ping(self, ip):
        return self.execute("ping "
                            "-c 1 "  # Number of pings
                            "-W 2 "  # Timeout for each ping
                            "%s" % ip)
