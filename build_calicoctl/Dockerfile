FROM ubuntu:14.04

WORKDIR /code/

RUN apt-get update

# Install felix so we get the python libs that we share with it.
RUN apt-get install -qy apt-transport-https ca-certificates software-properties-common
RUN add-apt-repository -y ppa:project-calico/icehouse
RUN apt-get update
RUN apt-get install -qy calico-felix

# Make an etcd available as some UTs rely on it.
RUN apt-get install -qy curl
RUN curl -L  https://www.github.com/coreos/etcd/releases/download/v2.0.10/etcd-v2.0.10-linux-amd64.tar.gz -o /tmp/etcd.tar.gz
RUN tar -zxvf /tmp/etcd.tar.gz -C /tmp --strip-components=1

# Install the python packages needed for running UTs and building calicoctl.
RUN apt-get install -qy python-dev python-pip
ADD requirements.txt /code/
RUN pip install -r requirements.txt

# Can't run pyinstaller as root so add a user - https://github.com/pyinstaller/pyinstaller/issues/1081
RUN useradd -d /home/user -m -s /bin/bash user
RUN chown -R user:user /code/
USER user
