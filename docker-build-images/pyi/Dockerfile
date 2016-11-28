# Build against wheezy for broadest libc compatibility.
FROM python:2.7-wheezy
MAINTAINER Shaun Crampton shaun@tigera.io

ARG UID
ARG GID

# Install Calico pre-reqs.
RUN pip install pyinstaller

# Install the frozen build requirements.  Use `make update-frozen-reqs` to
# update these.
ADD python/requirements_frozen.txt python/requirements_frozen.txt
RUN pip install -U -r python/requirements_frozen.txt

# To run some commands (git, tox) as non-root user, we need to have a valid
# passwd/group file.
# use `--force` and `-o` since tests can run under root and command will fail with duplicate error
RUN groupadd --force --gid=$GID user && useradd -o --home=/ --gid=$GID --uid=$UID user

RUN mkdir /code
WORKDIR /code
