"""
Configure BGP

Usage:
  calicoctl bgp peer add <PEER_IP> as <AS_NUM>
  calicoctl bgp peer remove <PEER_IP>
  calicoctl bgp peer show [--ipv4 | --ipv6]
  calicoctl bgp node-mesh [on|off]
  calicoctl bgp default-node-as [<AS_NUM>]

Options:
 --ipv4                   Show IPv4 information only.
 --ipv6                   Show IPv6 information only.
"""