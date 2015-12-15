<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.13.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Accessing Calico policy with Calico as a network plugin

Calico networking provides feature-rich policy for controlling access to and
from an endpoint.  However, Calico as a Docker network plugin has some 
limitations when using the standard Docker commands for managing networks and
containers.

The notable limitations are:
-  When using the Calico IPAM driver, it is not possible to join a container
   to more than one network
-  There is no built-in mechanism to create a network with complex policy 
   (currently the default policy is to allow full access between all endpoints
   connected to that network).

Despite these limitations, it is still possible to use the full Calico policy 
API by accessing the Calico data directly.

> Note that you must use both the Calico Network _and_ Calico IPAM drivers
> together.  Using the Calico IPAM driver  ensures _all_ traffic from the
> container is routed via the host vRouter and is subject to Calico policy.
> Using the default IPAM driver routes non-network traffic (i.e. destinations
> outside the network CIDR) via the Docker gateway bridge, and in this case
> may not be subjected to the policy configured on the host vRouter.

Calico policy is wrapped up in a "profile" object.  The default profile created
as part of the network creation simply contains a rule to allow traffic from
all endpoints configured to use that profile.

The Calico "endpoint" object is created as part of the `docker run`
command.  Each endpoint object contains a list of profiles, the policy of which
is applied in the list order.  This can be considered as the equivalent of
having a container in multiple networks, where each network uses a different
profile).

> As a comparison, when using [Calico without Docker networking](../without-docker-networking/README.md),
> the use of profiles is more transparent since it is necessary to explicitly
> create a profile and configure a container endpoint to use it.

Despite the Calico profile and endpoint configuration being "hidden", it is
still possible to determine the profile and endpoint IDs which will allow you
to use the [`calicoctl profile`](../../calicoctl/profile.md)
commands to configure [advanced network policy](../../AdvancedNetworkPolicy.md).

The Calico network driver directly maps the Docker Network "Id" to the Profile
name, and the Docker "EndpointID" to the Calico Endpoint ID.  You can use 
`docker network inspect` on a particular host to obtain the network ID and the
list of containers on that host that are attached to the network.

In the example below we run `docker network inspect testnet1` to inspect the 
network "testnet1".  This has returned a JSON blob that contains the network ID
and the Endpoint IDs (in this case there is a single endpoint):

    host1:~$ docker network inspect testnet1
    [
        {
            "Name": "testnet1",
            "Id": "46007b33d4dd56b13ede0f10bb427ba4481e3c0efe64960b0567dd53a80d3420",
            "Scope": "global",
            "Driver": "calico",
            "IPAM": {
                "Driver": "calico",
                "Config": [
                    {}
                ]
            },
            "Containers": {
                "6a853ddc289c4754684a93115c43aa73e3d7a4dd565e272cdc3f18ee3c09ba78": {
                    "EndpointID": "5a21f63bc17feb6b9c879bbbc271594dfa1483ddf9af5171efca7a2d509908e5",
                    "MacAddress": "ee:ee:ee:ee:ee:ee",
                    "IPv4Address": "10.0.0.2/24",
                    "IPv6Address": ""
                }
            },
            "Options": {}
        }
    ]

The Docker EndpointID is identical to the Endpoint ID used by Calico and
therefore can be manipulated using calicoctl.  For example, you can use
calicoctl to display the list of profiles assigned to this endpoint:

    host1:~$ calicoctl endpoint 5a21f63bc17feb6b9c879bbbc271594dfa1483ddf9af5171efca7a2d509908e5 profile show
    +------------------------------------------------------------------+
    |                               Name                               |
    +------------------------------------------------------------------+
    | 46007b33d4dd56b13ede0f10bb427ba4481e3c0efe64960b0567dd53a80d3420 |
    +------------------------------------------------------------------+

You can see that the profile name matches the Network ID returned by the
`network inspect` command above.

You can use the profile name to manipulate the Calico profile.  For example,
here we can display the rules that are contained in the profile:

    host1:~$ calicoctl profile 46007b33d4dd56b13ede0f10bb427ba4481e3c0efe64960b0567dd53a80d3420 rule show
    Inbound rules:
       1 allow from tag 46007b33d4dd56b13ede0f10bb427ba4481e3c0efe64960b0567dd53a80d3420
    Outbound rules:
       1 allow

## Further reading

For more details about advanced policy options read the 
[Advanced Network Policy tutorial](../../AdvancedNetworkPolicy.md).

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/calico-with-docker/docker-network-plugin/AdvancedPolicy.md?pixel)](https://github.com/igrigorik/ga-beacon)
