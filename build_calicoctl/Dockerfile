FROM calico/node

WORKDIR /code/

ADD requirements.txt /code/
RUN pip install -r requirements.txt

# Can't run pyinstaller as root so add a user.
RUN useradd -d /home/user -m -s /bin/bash user
RUN chown -R user /code/

CMD ["/bin/bash"]
USER user
ENV HOME /home/user

RUN curl -L  https://github.com/coreos/etcd/releases/download/v2.0.10/etcd-v2.0.10-linux-amd64.tar.gz -o /tmp/etcd.tar.gz
RUN tar -zxvf /tmp/etcd.tar.gz -C /tmp --strip-components=1
