# Build against wheezy for broadest libc compatibility.
FROM python:2.7-wheezy
MAINTAINER Shaun Crampton shaun@tigera.io

# Install Calico pre-reqs.
RUN pip install pyinstaller

# Install the frozen build requirements.  Use `make update-frozen-reqs` to
# update these.
ADD python/requirements_frozen.txt python/requirements_frozen.txt
RUN pip install -U -r python/requirements_frozen.txt

# To run some commands (git, tox) as non-root user, we need to have a valid
# passwd/group file.
ADD docker-build-images/passwd /passwd
RUN cat /passwd >> /etc/passwd
ADD docker-build-images/group /group
RUN cat /group >> /etc/group

RUN mkdir /code
WORKDIR /code
