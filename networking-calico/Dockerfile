FROM quay.io/coreos/etcd:v3.6.0 AS etcd

FROM python:3.8

COPY --from=etcd /usr/local/bin/etcd /usr/local/bin/etcd

RUN pip3 install tox==3.28.0
