FROM centos:7
MAINTAINER Shaun Crampton <shaun@tigera.io>
ENV STREAM el7

ARG UID
ARG GID

ADD install-centos-build-deps install-centos-build-deps
RUN ./install-centos-build-deps

# rpmbuild requires the current user to exist inside the container, copy in
# some user/group entries calculated by the makefile.
# use `--force` and `-o` since tests can run under root and command will fail with duplicate error
RUN groupadd --force --gid=$GID user && useradd -o --home=/ --gid=$GID --uid=$UID user

WORKDIR /code
