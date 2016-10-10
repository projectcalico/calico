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

# Install Calico pre-reqs.
ENV LD_LIBRARY_PATH=/usr/local/lib
ADD python/requirements.txt python/requirements.txt
RUN pip install -U -r python/requirements.txt; \
    pip install pyinstaller

# Install Calico into site-packages.  It's easier to package up the egg-info
# etc if we use the installed version.  Doing the install here rather than
# in the run-pyinstaller script means we don't have to run the latter as root
# (but it does mean that the build script needs to rebuild the container
# image each time).
COPY . /code
RUN cd /code/python && pip install -v .
