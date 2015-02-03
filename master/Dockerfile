# For details and docs - see https://github.com/phusion/baseimage-docker#getting_started
FROM phusion/baseimage:0.9.16

# Use baseimage-docker's init system.
CMD ["/sbin/my_init"]

RUN apt-get update

# Bird.
RUN apt-get install -y bird
RUN mkdir /etc/service/bird
ADD bird.sh /etc/service/bird/run

# Calico
RUN apt-get install -y python-zmq iptables ipset curl
RUN curl -L http://binaries.projectcalico.org/repo/key | apt-key add -
RUN echo "deb http://binaries.projectcalico.org/repo ./" >> /etc/apt/sources.list
RUN echo "Package: *" >> /etc/apt/preferences
RUN echo "Pin: origin binaries.projectcalico.org" >> /etc/apt/preferences
RUN echo "Pin-Priority: 1001" >> /etc/apt/preferences
RUN apt-get update
RUN apt-get dist-upgrade -y
RUN apt-get install -y calico-felix calico-acl-manager
RUN mkdir /etc/service/felix
ADD felix.sh /etc/service/felix/run

# Etcd
RUN curl -L  https://github.com/coreos/etcd/releases/download/v2.0.0/etcd-v2.0.0-linux-amd64.tar.gz -o etcd-v2.0.0-linux-amd64.tar.gz
RUN tar xzvf etcd-v2.0.0-linux-amd64.tar.gz
RUN mv etcd-v2.0.0-linux-amd64/etcd .
# TODO - Create service file

# Confd
RUN curl -L https://github.com/kelseyhightower/confd/releases/download/v0.6.3/confd-0.6.3-linux-amd64 -o confd
# TODO - Create service file
# TODO - Create a confdir
# TODO - And create the TOML templates


# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*