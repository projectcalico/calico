# Building Binaries

You will require 2 binary builds to use the Calico Docker Prototype:
 1. The `calico/node` Docker image which contains the Calico services.
 2. The `calicoctl` control binary to control your Calico-enabled cluster from the CLI.

## Building the Docker Image

 From the root directory of the checked out repository, run

    ./build_node.sh

This builds the Dockerfile giving it the name `calico/node:latest`, which is the default image name `calicoctl` will look for when starting Calico services.

## Building `calicoctl` CLI Tool - mainline

    ./create_binary.sh

## Building `calicoctl` CLI Tool - virtualenv

We use a Debian-based container to build the `calicoctl` tool above.  If that is not appropriate to your Linux distribution, you can build in a python virtualenv on your distro.

Set up a [Python Virtual Environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/)

    pip install virtualenv
    virtualenv venv

Activate your virtual env.

    source venv/bin/activate

Install the build requirements.

    pip install -r requirements.txt

Build `calicoctl` with `pyinstaller`.

    pyinstaller ../calicoctl.py -a -F -s --clean
