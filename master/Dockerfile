# For details and docs - see https://github.com/phusion/baseimage-docker#getting_started
FROM phusion/baseimage:0.9.16

# Use baseimage-docker's init system.
CMD ["/sbin/my_init"]

RUN apt-get update

# Calico (for ACL Manager)
RUN apt-get install -y python-zmq iptables ipset curl
RUN curl -L http://binaries.projectcalico.org/repo/key | apt-key add -
RUN echo "deb http://binaries.projectcalico.org/repo ./" >> /etc/apt/sources.list
RUN echo "Package: *" >> /etc/apt/preferences
RUN echo "Pin: origin binaries.projectcalico.org" >> /etc/apt/preferences
RUN echo "Pin-Priority: 1001" >> /etc/apt/preferences
RUN apt-get update
RUN apt-get dist-upgrade -y
RUN apt-get install -y calico-felix calico-acl-manager
RUN mkdir /etc/service/aclmanager
ADD aclmanager.sh /etc/service/aclmanager/run

# Confd
RUN curl -L https://github.com/kelseyhightower/confd/releases/download/v0.7.1/confd-0.7.1-linux-amd64 -o confd
RUN chmod +x confd
RUN mkdir /etc/service/confd
ADD confd.sh /etc/service/confd/run


# Plugin
RUN apt-get install -y python-zmq python-flask python-docopt
ADD plugin.py plugin.py
RUN mkdir /etc/service/pluginnetwork
ADD plugin_network.sh /etc/service/pluginnetwork/run
RUN mkdir /etc/service/pluginendpoint
ADD plugin_endpoint.sh /etc/service/pluginendpoint/run

ADD rc.local /etc/rc.local
ADD conf.d conf.d
ADD templates templates
# RUN mkdir -p /config/data
RUN mkdir -p /var/log/calico

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*