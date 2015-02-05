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

# Confd
RUN curl -L https://github.com/kelseyhightower/confd/releases/download/v0.7.1/confd-0.7.1-linux-amd64 -o confd
RUN chmod +x confd
RUN mkdir /etc/service/confd
ADD confd.sh /etc/service/confd/run

# Powerstrip
RUN apt-get -qy install python-pip
RUN apt-get -qy install python-dev
RUN apt-get -qy install python-pyasn1
RUN apt-get -qy install libyaml-dev
RUN apt-get -qy install libffi-dev
RUN apt-get -qy install libssl-dev
RUN mkdir /powerstrip
RUN cd /powerstrip
RUN curl -L https://github.com/ClusterHQ/powerstrip/archive/v0.0.1.tar.gz -o powerstrip.tar.gz
RUN tar -xzf powerstrip.tar.gz
RUN python setup.py install

# Powerstrip Calico Adapter
RUN apt-get -y install -q build-essential
# Already installed by Powerstrip
# RUN apt-get -y install -q python-dev libffi-dev libssl-dev python-pip
RUN mkdir /adapter
ADD adapter /adapter
RUN pip install -r /adapter/requirements.txt

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD rc.local /etc/rc.local
ADD conf.d conf.d
ADD templates templates
RUN mkdir /config
RUN mkdir -p /var/log/calico