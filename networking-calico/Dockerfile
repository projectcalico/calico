# The versions come from the Makefile, which a native run installs from too.
ARG ETCD_VERSION
ARG PYTHON_VERSION

FROM quay.io/coreos/etcd:${ETCD_VERSION} AS etcd

FROM python:${PYTHON_VERSION}

COPY --from=etcd /usr/local/bin/etcd /usr/local/bin/etcd

ARG TOX_VERSION
RUN pip3 install tox==${TOX_VERSION}
