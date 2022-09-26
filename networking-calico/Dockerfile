FROM quay.io/coreos/etcd:v3.3.11 as etcd

FROM python:3.8

COPY --from=etcd /usr/local/bin/etcd /usr/local/bin/etcd

RUN pip3 install tox
