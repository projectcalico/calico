"""Configure the main calico/node container and establish Calico networking

Usage:
  calicoctl node [--ip=<IP>] [--ip6=<IP6>] [--node-image=<DOCKER_IMAGE_NAME>] [--as=<AS_NUM>] [--log-dir=<LOG_DIR>]
  calicoctl node stop [--force]
  calicoctl node bgp peer add <PEER_IP> as <AS_NUM>
  calicoctl node bgp peer remove <PEER_IP>
  calicoctl node bgp peer show [--ipv4 | --ipv6]

Options:
 --node-image=<DOCKER_IMAGE_NAME>    Docker image to use for
                          Calico's per-node container
                          [default: calico/node:libnetwork-release]
 --log-dir=<LOG_DIR>      The directory for logs [default: /var/log/calico]
 --ip=<IP>                The local management address to use.
 --ip6=<IP6>              The local IPv6 management address to use.
 --as=<AS_NUM>            The AS number to assign to the node.
 --ipv4                   Show IPv4 information only.
 --ipv6                   Show IPv6 information only.
"""