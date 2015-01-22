#!/bin/sh

set -e
set -x

git clone https://github.com/metaswitch/calico-docker.git
mv calico-docker/* -t .

echo "172.17.8.101 core-01" >> /etc/hosts
echo "172.17.8.102 core-02" >> /etc/hosts

# Add a super-insecure hard-coded key to allow different nodes
# in the cluster to ssh to the master and transfer the config
# for newly-created docker containers.

mkdir -p /root/.ssh/
chmod -R go-rwx /root/.ssh

cat <<EOF > /root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAqjT/tu+11W9sJiqaJnsh0TkiClZZVGAiYV7EUAsJTU3upKtz
zfgCRCkcdqLB9GQgH9hg9SE92y1sUizLl7pquz+7wg8eNN9VsjQrhgl6YX3fdo72
nFDdhH3S6m9Xn9viEssBH5ZNdNFN2n/A5uAE8rWwnEqbYj0ESpSunQAaz6mrTrZr
8pGks6YOV4W90gc6GnhnVOP4bvkjvW+RcZ49s4+iydjrUhu5iZnDZpTwN91JXASQ
XTFcafRXRKpkWYEqgZmhoJMR7N/8B74uryRTTkvTAVRLRh8wmIPtPKobLRCkrAu3
W74xLA5eY8ATUk4Y3v9I3cH4Ot1ajC2JEamwmwIDAQABAoIBAHOxkLvFVqDcmvOa
c6uCeOshXa0PIqtCqTvsUZ5i0hDUz0jpLc8sLEYud6WAXjwDrv5WcxlMXiJUTtPQ
lRbuZMwgtzxiUFL6F+MIqSjz2lbYW4PYC3MXWGtNp4co5bPIn3PMv1e8L6we9T93
JSUJ0vMzYvfpkpMFDJyxUbtwLclG29lfyEcgugaN748TcSVSZKT+PupL4Vdb0U6/
c2j3EE0iVw0xpAgHgvoI7p+ii0ZMGpxQrzXusBMgfLOosWgYej6tfZApI31RGAsM
qcND6Po+dyVE3j+yQEFSPgq/CJrGvLY2cvldGfN9JjQYo6JzbNbhhAn/TM8WP19l
ZruBpAkCgYEA3cc8T8LbliB8fg2B6KAfcXbeQLKUIuQ7JErdjMVAJcwWnMxuSyqL
BK6QZSCiTT7whrQTK9OM+3dP0ZOPG3jl6QDy89qfTY/lKCBIqMhGbCTLrPCsRDHm
iViUs9nNHOS7IVehYm43zkCwNYJaQwhOaSlq3NWC92fAPZgFFcPn9nUCgYEAxHiT
67OfLaPeTEVJD/83UCUcfkTI64cRsITBI/8T4OI+ymYePRgaeReVsykqy1Um72XR
ux1Pl11hHqVtS8fbHg+/FXU6vz2AZatbCZPIRs9ZU8U5feyPaAhGQaZqbhYiYad1
55R3oID6VD/rxYxCIl3RvAMrdyXWdEzsZuiWyM8CgYBPXYZC0Ou+HOAQSAsuUWcP
NsewhXenyN81TKleQBSFsjSBZlMuCQp44XOBDR2n4Rc4TWby7yDruLXSvSigXzJ/
oLxQ8fLCUfVi17LI2+r/tmdA+1vah7UFf7KvbgkOBvjEpNR3IhRMdi/Y5k4g4O8W
iSDZ6HqWyQUtxaJEOLhhJQKBgCSgviMBF7nwhO7/M8HRuMQuRwObW0HdqoSYG1HU
qiYQx9f/9b86ESVmKjh+gkXqGBolh1Y0/rOfaw3FlXy9Q7J1CRC9DDi/BILv0UcV
0A6zdVnSuQcq5QlmEYMHvWvMoJhIGgkUesDnisPOLuxjW6kAiKteg+nwmeyQsrn0
vretAoGASBmzBuc14TbcEKOq8y8cwwQ+rKR5UZmh7R0LFeJ73p+Rkb5PiJZyyDXV
OBCYk1TBeBZqJ9+O7T4AVE8AOUwLPjBXRqaBOUJ1SaM1uyF8DuzmJQOWuGNhGHet
nOxY5gICvoeuE5/txB/Gvq+tpoOsouB5glYCloM05hYmCbGrIMA=
-----END RSA PRIVATE KEY-----
EOF

cat <<EOF > /root/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqNP+277XVb2wmKpomeyHROSIKVllUYCJhXsRQCwlNTe6kq3PN+AJEKRx2osH0ZCAf2GD1IT3bLWxSLMuXumq7P7vCDx4031WyNCuGCXphfd92jvacUN2EfdLqb1ef2+ISywEflk100U3af8Dm4ATytbCcSptiPQRKlK6dABrPqatOtmvykaSzpg5Xhb3SBzoaeGdU4/hu+SO9b5Fxnj2zj6LJ2OtSG7mJmcNmlPA33UlcBJBdMVxp9FdEqmRZgSqBmaGgkxHs3/wHvi6vJFNOS9MBVEtGHzCYg+08qhstEKSsC7dbvjEsDl5jwBNSThje/0jdwfg63VqMLYkRqbCb core@core-02
EOF

if ! grep @core-02 /root/.ssh/authorized_keys; then
cat <<EOF >> /root/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqNP+277XVb2wmKpomeyHROSIKVllUYCJhXsRQCwlNTe6kq3PN+AJEKRx2osH0ZCAf2GD1IT3bLWxSLMuXumq7P7vCDx4031WyNCuGCXphfd92jvacUN2EfdLqb1ef2+ISywEflk100U3af8Dm4ATytbCcSptiPQRKlK6dABrPqatOtmvykaSzpg5Xhb3SBzoaeGdU4/hu+SO9b5Fxnj2zj6LJ2OtSG7mJmcNmlPA33UlcBJBdMVxp9FdEqmRZgSqBmaGgkxHs3/wHvi6vJFNOS9MBVEtGHzCYg+08qhstEKSsC7dbvjEsDl5jwBNSThje/0jdwfg63VqMLYkRqbCb core@core-02
EOF
fi

chmod -R go-rwx /root/.ssh
chown -R core:core .

