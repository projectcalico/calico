

class DockerNetwork(object):
    """
    A Docker network created by libnetwork.

    Docker networks provide mutual connectivity to the endpoints attached to
    them (and endpoints join/leave sandboxes which are network namespaces used
    by containers).
    """

    def __init__(self, host, name, driver="calico"):
        """
        Create the network.
        :param host: The Docker Host which creates the network (note that
        networks
        :param name: The name of the network.  This must be unique per cluster
        and it the user-facing identifier for the network.  (Calico itself will
        get a UUID for the network via the driver API and will not get the
        name).
        :param driver: The name of the network driver to use.  (The Calico
        driver is the default.)
        :return: A DockerNetwork object.
        """
        self.name = name
        self.driver = driver

        self.init_host = host
        """The host which created the network."""

        args = [
            "docker", "network", "create",
            "--driver=%s" % driver,
            name,
        ]
        command = ' '.join(args)
        self.uuid = host.execute(command).rstrip()

    def __str__(self):
        return self.name



