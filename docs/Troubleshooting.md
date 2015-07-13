# Troubleshooting

## `sudo docker run` and environment variables.

If you use `sudo` for commands like `docker run`, remember that your environment variables will not be transferred to the `sudo` environment.  You can set environment variables for `sudo` commands like this.

    sudo DOCKER_HOST=localhost:2377 docker run -td -e CALICO_IP=192.168.100.1 busybox

## Ubuntu (or GNOME) NetworkManager

Disable [NetworkManager](https://help.ubuntu.com/community/NetworkManager) before attepting to use Calico networking.

NetworkManager manipulates the routing table for interfaces in the default network namespace where Calico veth pairs are anchored for connections to containers.  This can interfere with the Calico agent's ability to route correctly. 

## etcd.EtcdException: No more machines in the cluster

If you see this exception, it means `calicoctl` can't communicate with your etcd cluster.  Ensure etcd is up and listening on `localhost:4001`

## Basic checks
Running `ip route` shows what routes have been programmed. Routes from other hosts should show that they are programmed by bird.

If your hosts reboot themselves with a message from `locksmithd` your cached CoreOS image is out of date.  Use `vagrant box update` to pull the new version.  I recommend doing a `vagrant destroy; vagrant up` to start from a clean slate afterwards.

If you hit issues, please raise tickets. Diags can be collected and easily uploaded with the `sudo ./calicoctl diags --upload` command.