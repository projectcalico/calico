class Workload(object):
    def __init__(self, host, name, ip, image="busybox", use_powerstrip=True):
        self.host = host
        self.name = name
        self.ip = ip

        host.execute("docker run "
                     "--env CALICO_IP=%s "
                     "--name %s "
                     "--tty "
                     "--interactive "
                     "--detach "
                     "%s" % (ip, name, image),
                     use_powerstrip=use_powerstrip)
