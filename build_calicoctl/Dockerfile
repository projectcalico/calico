# This image is based on the "main" calico/node image. It shares many of the
# dependencies which makes it a good base for an image used for building and
# unit testing
FROM calico/node

WORKDIR /code/

ADD requirements.txt /code/
RUN pip install -r requirements.txt

# Can't run pyinstaller as root so add a user.
RUN useradd -d /home/user -m -s /bin/bash user
RUN chown -R user /code/
USER user
# The HOME env var should be set automatically, but for some reason it's not...
ENV HOME /home/user

# Override CMD. The base image uses an init system to run some services that
# we don't want to be running during UTs and builds.
CMD ["/bin/bash"]


RUN curl -L  https://www.github.com/coreos/etcd/releases/download/v2.0.10/etcd-v2.0.10-linux-amd64.tar.gz -o /tmp/etcd.tar.gz
RUN tar -zxvf /tmp/etcd.tar.gz -C /tmp --strip-components=1
