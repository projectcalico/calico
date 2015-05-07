#!/bin/sh
set -e
set -x

# Set it up
docker rm -f node1 node2 etcd || true
docker run -d --net=host --name etcd quay.io/coreos/etcd:v2.0.10
dist/calicoctl reset || true

# Run various commands with invalid IPs.
(! dist/calicoctl node --ip=127.a.0.1)
(! dist/calicoctl node --ip=aa:bb::cc)
(! dist/calicoctl node --ip=127.0.0.1 --ip6=127.0.0.1)
(! dist/calicoctl node --ip=127.0.0.1 --ip6=aa:bb::zz)
(! dist/calicoctl bgppeer rr add 127.a.0.1)
(! dist/calicoctl bgppeer rr add aa:bb::zz)
(! dist/calicoctl pool add 127.a.0.1)
(! dist/calicoctl pool add aa:bb::zz)
(! dist/calicoctl container node1 ip add 127.a.0.1)
(! dist/calicoctl container node1 ip add aa:bb::zz)
(! dist/calicoctl container add node1 127.a.0.1)
(! dist/calicoctl container add node1 aa:bb::zz)

# Add some pools and BGP peers and check the show commands
dist/calicoctl bgppeer rr add 1.2.3.4
dist/calicoctl bgppeer rr show
dist/calicoctl bgppeer rr show --ipv4
dist/calicoctl bgppeer rr show --ipv6
dist/calicoctl bgppeer rr show | grep 1.2.3.4
dist/calicoctl bgppeer rr show --ipv4 | grep 1.2.3.4
(! dist/calicoctl bgppeer rr show --ipv6 | grep 1.2.3.4)
dist/calicoctl bgppeer rr remove 1.2.3.4
(! dist/calicoctl bgppeer rr show | grep 1.2.3.4)

dist/calicoctl bgppeer rr add aa:bb::ff
dist/calicoctl bgppeer rr show
dist/calicoctl bgppeer rr show --ipv4
dist/calicoctl bgppeer rr show --ipv6
dist/calicoctl bgppeer rr show | grep aa:bb::ff
(! dist/calicoctl bgppeer rr show --ipv4 | grep aa:bb::ff)
dist/calicoctl bgppeer rr show --ipv6 | grep aa:bb::ff
dist/calicoctl bgppeer rr remove aa:bb::ff
(! dist/calicoctl bgppeer rr show | grep aa:bb::ff)

dist/calicoctl pool add 1.2.3.4
dist/calicoctl pool show
dist/calicoctl pool show --ipv4
dist/calicoctl pool show --ipv6
dist/calicoctl pool show | grep 1.2.3.4/32
dist/calicoctl pool show --ipv4 | grep 1.2.3.4/32
(! dist/calicoctl pool show --ipv6 | grep 1.2.3.4/32)
dist/calicoctl pool remove 1.2.3.4
(! dist/calicoctl pool show | grep 1.2.3.4/32)

dist/calicoctl pool add 1.2.3.0/24
dist/calicoctl pool show
dist/calicoctl pool show --ipv4
dist/calicoctl pool show --ipv6
dist/calicoctl pool show | grep 1.2.3.0/24
dist/calicoctl pool show --ipv4 | grep 1.2.3.0/24
(! dist/calicoctl pool show --ipv6 | grep 1.2.3.0/24)
dist/calicoctl pool remove 1.2.3.0/24
(! dist/calicoctl pool show | grep 1.2.3.0/24)

dist/calicoctl pool add aa:bb::ff
dist/calicoctl pool show
dist/calicoctl pool show --ipv4
dist/calicoctl pool show --ipv6
dist/calicoctl pool show | grep aa:bb::ff/128
(! dist/calicoctl pool show --ipv4 | grep aa:bb::ff/128)
dist/calicoctl pool show --ipv6 | grep aa:bb::ff/128
dist/calicoctl pool remove aa:bb::ff/128
(! dist/calicoctl pool show | grep aa:bb::ff/128)

# Not used anywhere else in the tests; added here for completeness.
PROFILE=TEST_PROFILE
dist/calicoctl profile add $PROFILE
TAG=TEST_TAG

dist/calicoctl profile $PROFILE tag add $TAG
dist/calicoctl profile $PROFILE tag remove $TAG
dist/calicoctl profile $PROFILE tag show
dist/calicoctl profile $PROFILE rule json
dist/calicoctl profile $PROFILE rule show
echo '{
  "id": "TEST_PROFILE",
  "inbound_rules": [
    {
      "action": "allow",
      "src_tag": "TEST_PROFILE"
    },
    {
      "action": "deny"
    }
  ],
  "outbound_rules": [
    {
      "action": "allow"
    }
  ]
}' | dist/calicoctl profile $PROFILE rule update

echo "Tests completed successfully"
