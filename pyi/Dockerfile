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
RUN yum install -y libffi-devel libffi yajl
ADD felix_requirements.txt felix_requirements.txt
RUN pip install -U -r felix_requirements.txt

# Required for IP SAN support.
RUN pip install urllib3>=1.18
RUN pip install pyopenssl ndg-httpsclient pyasn1

# And pyinstaller...
RUN pip install pyinstaller

# Install Calico into site-packages.  It's easier to package up the egg-info
# etc if we use the installed version.  Doing the install here rather than
# in the run-pyinstaller script means we don't have to run the latter as root
# (but it does mean that the build script needs to rebuild the container
# image each time).
COPY . /code
RUN cd /code && pip install .
