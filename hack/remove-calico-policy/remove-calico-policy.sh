#!/bin/sh

# Set FORWARD action to ACCEPT so outgoing packets can go through POSTROUTING chains.
echo "Setting default FORWARD action to ACCEPT..."
iptables -P FORWARD ACCEPT

# Make sure ip_forward sysctl is set to allow ip forwarding.
sysctl -w net.ipv4.ip_forward=1

echo "Starting the flush Calico policy rules..."
echo "Make sure calico-node DaemonSet is stopped before this gets executed."

echo "Flushing all the calico iptables chains in the nat table..."
iptables-save -t nat | grep -oP '(?<!^:)cali-[^ ]+' | while read line; do iptables -t nat -F $line; done

echo "Flushing all the calico iptables chains in the raw table..."
iptables-save -t raw | grep -oP '(?<!^:)cali-[^ ]+' | while read line; do iptables -t raw -F $line; done

echo "Flushing all the calico iptables chains in the mangle table..."
iptables-save -t mangle | grep -oP '(?<!^:)cali-[^ ]+' | while read line; do iptables -t mangle -F $line; done

echo "Flushing all the calico iptables chains in the filter table..."
iptables-save -t filter | grep -oP '(?<!^:)cali-[^ ]+' | while read line; do iptables -t filter -F $line; done

echo "Cleaning up calico rules from the nat table..."
iptables-save -t nat | grep -e '--comment "cali:' | cut -c 3- | sed 's/^ *//;s/ *$//' | xargs -l1 iptables -t nat -D

echo "Cleaning up calico rules from the raw table..."
iptables-save -t raw | grep -e '--comment "cali:' | cut -c 3- | sed 's/^ *//;s/ *$//' | xargs -l1 iptables -t raw -D

echo "Cleaning up calico rules from the mangle table..."
iptables-save -t mangle | grep -e '--comment "cali:' | cut -c 3- | sed 's/^ *//;s/ *$//' | xargs -l1 iptables -t mangle -D

echo "Cleaning up calico rules from the filter table..."
iptables-save -t filter | grep -e '--comment "cali:' | cut -c 3- | sed 's/^ *//;s/ *$//' | xargs -l1 iptables -t filter -D

# Set the CLUSTER_CIDR environment variable to the appropriate CIDR for this cluster if Calico is adding the traffic.
if [ "$CLUSTER_CIDR" != "" ]; then
    clusterCIDR=$CLUSTER_CIDR

    # Set up NAT rule so traffic gets masqueraded if it is going to any subnet other than cluster-cidr.
    echo "Adding masquerade rule for traffic going from $clusterCIDR to ! $clusterCIDR"

    # Create a new chain in nat table.
    iptables -t nat -N cali-brb-masq

    # Append that chain to POSTROUTING table.
    iptables -t nat -A POSTROUTING -m comment --comment "cali:masq-outgoing" -j cali-brb-masq

    # Add MASQUERADE rule for traffic from clusterCIDR to non-clusterCIDR.
    iptables -t nat -A cali-brb-masq -s $clusterCIDR ! -d $clusterCIDR -j MASQUERADE
fi

# Sleep forever so DaemonSet doesn't die.
while true; do echo "sleeping..."; sleep 3600; done
