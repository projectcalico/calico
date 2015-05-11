FROM calico/node

CMD ["/sbin/my_init"]

WORKDIR /code/

ADD requirements.txt /code/
RUN pip install -r requirements.txt

# Can't run pyinstaller as root so add a user.
RUN useradd -d /home/user -m -s /bin/bash user
RUN chown -R user /code/
