FROM ringo/scientific:6.5
MAINTAINER Shaun Crampton shaun@tigera.io

# Install build prereqs.
RUN yum -y groupinstall "Development tools"; \
    yum -y install zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel

# Build python and conntrack.
ENV PY_VERSION=2.7.11
ADD pyi/get-prereqs.sh get-prereqs.sh
RUN ./get-prereqs.sh
ADD pyi/build-prereqs.sh build-prereqs.sh
RUN ./build-prereqs.sh

# Install Calico pre-reqs.
ENV LD_LIBRARY_PATH=/usr/local/lib
RUN yum install -y iptables-ipv6 ipset iptables libffi-devel libffi yajl
ADD felix_requirements.txt felix_requirements.txt
RUN pip install -U -r felix_requirements.txt

# And pyinstaller...
RUN pip install pyinstaller
COPY . /code
RUN cd /code && pip install .