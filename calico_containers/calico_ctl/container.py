"""
Configure containers and their addresses

Usage:
  calicoctl container <CONTAINER> ip (add|remove) <IP> [--interface=<INTERFACE>]
  calicoctl container <CONTAINER> endpoint-id show
  calicoctl container add <CONTAINER> <IP> [--interface=<INTERFACE>]
  calicoctl container remove <CONTAINER> [--force]

Options:
 --interface=<INTERFACE>  The name to give to the interface in the container
                          [default: eth1]
"""