FROM quay.io/coreos/etcd:v3.4.20 AS etcd

FROM python:3.8

COPY --from=etcd /usr/local/bin/etcd /usr/local/bin/etcd

RUN pip3 install tox==3.25.1
