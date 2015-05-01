FROM phusion/baseimage:0.9.16
RUN add-apt-repository -y ppa:project-calico/icehouse && \
    apt-get update -qq && \
    apt-get install -qy \
        python \
        python-pip \
        libffi-dev \
        libssl-dev \
        libyaml-dev \
        python-dev \
        python-etcd \
        git && \
    apt-get clean
WORKDIR /code/

ADD requirements.txt /code/
RUN pip install -r requirements.txt

# Can't run pyinstaller as root so add a user.
RUN useradd -d /home/user -m -s /bin/bash user
RUN chown -R user /code/
