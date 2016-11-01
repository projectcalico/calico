FROM centos:7
MAINTAINER Shaun Crampton <shaun@tigera.io>
ENV STREAM el7

ADD install-centos-build-deps install-centos-build-deps
RUN ./install-centos-build-deps

# rpmbuild requires the current user to exist inside the container, copy in
# some user/group entries calculated by the makefile.
ADD passwd /passwd
RUN cat /passwd >> /etc/passwd
ADD group /group
RUN cat /group >> /etc/group

WORKDIR /code
