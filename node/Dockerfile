# For details and docs - see https://github.com/phusion/baseimage-docker#getting_started
FROM phusion/baseimage:0.9.16

# Use baseimage-docker's init system.
CMD ["/sbin/my_init"]

# Install Calico APT repo.  Note, we delay the apt-get update until 
# below so that the update is done in the same FS layer as the 
# install, making it unlikely to be out of sync.
RUN curl -L http://calico-jenkins/debian/pr/gevent-proto/key | apt-key add - && \
    echo "deb http://calico-jenkins/debian/pr/gevent-proto ./" >> /etc/apt/sources.list && \
    echo "Package: *" >> /etc/apt/preferences &&\
    echo "Pin: origin calico-jenkins" >> /etc/apt/preferences && \
    echo "Pin-Priority: 1001" >> /etc/apt/preferences

# Install dependencies shared with the master node.  If we can keep this
# in sync then we'll share an FS layer with the master to speed downloads.
RUN apt-get update && \
    apt-get install -qy \
        calico-felix \
        ipset \
        iptables \
        libffi-dev \
        libssl-dev \
        libyaml-dev \
        python-dev \
        python-docopt \
        python-pip \
        python-pyasn1 \
        python-gevent && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    pip install python-etcd

# Confd
RUN curl -L https://github.com/kelseyhightower/confd/releases/download/v0.7.1/confd-0.7.1-linux-amd64 -o confd && \
    chmod +x confd

# Node-specific apt-get.
RUN apt-get update && \
    apt-get install -qy \
        bird \
        bird6 \
        build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Powerstrip
RUN curl -L https://github.com/ClusterHQ/powerstrip/archive/v0.0.1.tar.gz \
            -o powerstrip.tar.gz && \
    tar -xzf powerstrip.tar.gz && \
    rm powerstrip.tar.gz && \
    mv powerstrip-0.0.1 powerstrip && \
    cd powerstrip && \
    sed -i s/2375/2377/ powerstrip.tac && \
    python setup.py install

# Copy in our custom configuration files etc.
COPY root_overlay /

# Install Powerstrip Calico Adapter dependencies.
RUN pip install -r /adapter/requirements.txt
