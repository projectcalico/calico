FROM phusion/baseimage
MAINTAINER Dan Osborne <dan@projectcalico.org>

# Install Mesos
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv E56151BF
ENV DISTRO=ubuntu
ENV CODENAME=trusty-unstable

RUN echo "deb http://repos.mesosphere.com/${DISTRO} ${CODENAME} main" | \
  tee /etc/apt/sources.list.d/mesosphere.list
RUN apt-get -y update
RUN apt-get -qy install \
  build-essential       \
  make                  \
  python-dev            \
  dnsutils              \
  curl                  \
  iptables              \
  python-pip            \
  --no-install-recommends

RUN pip install --upgrade pip

###################
# Docker
###################
# Install Docker from Docker Inc. repositories.
RUN curl -sSL https://get.docker.com/ | sh

# Define additional metadata for our image.
VOLUME /var/lib/docker

RUN apt-get -y install mesos libevent-dev

####################
# Mesos-DNS
####################
RUN curl -LO https://github.com/mesosphere/mesos-dns/releases/download/v0.5.0/mesos-dns-v0.5.0-linux-amd64 && \
    mv mesos-dns-v0.5.0-linux-amd64 /usr/bin/mesos-dns && \
    chmod +x /usr/bin/mesos-dns

####################
# Demo Files
####################
# redis
# RUN pip install flask redis
# WORKDIR /root
# RUN curl -LO http://download.redis.io/releases/redis-3.2.0.tar.gz
# RUN tar -xvf /root/redis-3.2.0.tar.gz
# WORKDIR /root/redis-3.2.0
# RUN make && make install

# flask
# ADD ./demo/app.py /root/

#################
# Init scripts
#################
ADD ./init_scripts/etc/ /etc/


######################
# Calico
######################
ENV CALICO_NODE_VERSION=v0.19.0
COPY ./images/calico-node-$CALICO_NODE_VERSION.tar /images/calico-node-$CALICO_NODE_VERSION.tar
# COPY ./images/redis.tar /images/redis.tar
RUN curl -L -o /usr/local/bin/calicoctl https://github.com/projectcalico/calico-docker/releases/download/$CALICO_NODE_VERSION/calicoctl
RUN chmod +x /usr/local/bin/calicoctl

ADD ./cni/ /cni/

