# Run this script before running "make test-kdd"
docker stop calico-local-apiserver
docker stop calico-etcd
docker rm calico-local-apiserver
docker rm calico-etcd

sleep 10

make test-kdd | tee l.l
