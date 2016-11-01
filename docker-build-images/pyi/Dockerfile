# SL6.5 has the oldest version of glibc that we support.  Build against that.
FROM ringo/scientific:6.5
MAINTAINER Shaun Crampton shaun@tigera.io

# Install build prereqs.
RUN yum -y groupinstall "Development tools"; \
    yum -y install zlib-devel bzip2-devel openssl-devel ncurses-devel \
                   sqlite-devel iptables-ipv6 ipset iptables libffi-devel \
                   libffi yajl

# Build Python.
ENV PY_VERSION=2.7.11
ADD docker-build-images/pyi/get-prereqs.sh get-prereqs.sh
ADD docker-build-images/pyi/build-prereqs.sh build-prereqs.sh
RUN ./get-prereqs.sh && \
    ./build-prereqs.sh
ENV LD_LIBRARY_PATH=/usr/local/lib

# Install newer version of git, needed for diff-cover.
RUN wget http://repository.it4i.cz/mirrors/repoforge/redhat/el6/en/x86_64/rpmforge/RPMS/rpmforge-release-0.5.3-1.el6.rf.x86_64.rpm && \
    yum install -y rpmforge-release-0.5.3-1.el6.rf.x86_64.rpm && \
    yum install -y --enablerepo=rpmforge-extras git

# Install Calico pre-reqs.
RUN pip install pyinstaller

# Install the frozen build requirements.  Use `make update-frozen-reqs` to
# update these.
ADD python/requirements_frozen.txt python/requirements_frozen.txt
RUN pip install -U -r python/requirements_frozen.txt

# tox needs the current user to exist in /etc/passwd for some reason.
ADD docker-build-images/passwd /passwd
RUN cat /passwd >> /etc/passwd
ADD docker-build-images/group /group
RUN cat /group >> /etc/group

RUN mkdir /code
WORKDIR /code
