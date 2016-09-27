# If IPIP is enabled, the host requires an IP address for its tunnel
# device, which is in an IPIP pool.  Without this, a host can't originate
# traffic to a pool address because the response traffic would not be
# routed via the tunnel (likely being dropped by RPF checks in the fabric).
#
# This is a oneshot python script that queries etcd for existing pools.
# If any pool has --ipip, it will ensure this host's tunl0 interface
# has been assigned an IP from the ipip pool.

import os
from startup import _ensure_host_tunnel_addr, _remove_host_tunnel_addr
from pycalico.ipam import IPAMClient

def main():
	ipv4_pools = client.get_ip_pools(4)
	ipip_pools = [p for p in ipv4_pools if p.ipip]

	if ipip_pools:
	    # IPIP is enabled, make sure the host has an address for its tunnel.
	    _ensure_host_tunnel_addr(ipv4_pools, ipip_pools)
	else:
	    # No IPIP pools, clean up any old address.
	    _remove_host_tunnel_addr()

hostname = os.getenv("HOSTNAME")
client = IPAMClient()

if __name__ == "__main__":
    main()
