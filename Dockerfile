# For details and docs - see https://github.com/phusion/baseimage-docker#getting_started
FROM phusion/baseimage:0.9.16

# Use baseimage-docker's init system.
CMD ["/sbin/my_init"]

# Ensure UTF-8, required for add-apt-repository call.
RUN locale-gen en_US.UTF-8
ENV LANG       en_US.UTF-8
ENV LC_ALL     en_US.UTF-8

RUN add-apt-repository -y ppa:cz.nic-labs/bird && \
    add-apt-repository -y ppa:project-calico/icehouse && \
    apt-get update && \
    apt-get install -qy \
        calico-felix \
        bird \
        bird6 \
        build-essential \
        ipset \
        iptables \
        libffi-dev \
        libssl-dev \
        libyaml-dev \
        python-dev \
        python-docopt \
        python-pip \
        python-pyasn1 \
        python-netaddr \
        git \
        python-gevent \
        python-etcd \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Confd
RUN curl -L https://www.github.com/kelseyhightower/confd/releases/download/v0.9.0/confd-0.9.0-linux-amd64 -o confd && \
    chmod +x confd

# Install Powerstrip Calico Adapter dependencies.
ADD calico_containers/driver/requirements.txt /driver/
RUN pip install -r /driver/requirements.txt

# Copy in our custom configuration files etc. We do this last to speed up
# builds for developer, as it's thing they're most likely to change.
COPY node_filesystem /

COPY calico_containers/driver /calico_containers/driver
COPY calico_containers/__init__.py /calico_containers/
