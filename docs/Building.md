<!--- master only -->
> ![warning](images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.13.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Building and testing calico-containers images

This document describes how to build the `calicoctl` binary and the `calico/node` Docker image, and how to run the Calico Docker test suites.


## Building Calico Docker images and running the test suites

You will require two image builds to use Calico Docker:
 1. The `calico/node` Docker image which contains the Calico services.
 2. The `calicoctl` control binary to control your Calico-enabled cluster from the CLI.

### Building the 'calico/node' Docker Image

From the root directory of the checked out repository, run

    make node

This builds the Dockerfile giving it the name `calico/node:latest`, which is the default image name 
of the master branch version of `calicoctl` will look for when starting Calico services.

### Building `calicoctl` CLI Tool

Our makefile target uses a Debian-based container to build the `calicoctl` tool.  If this is not appropriate
for your Linux distribution, you can build the tool in a python virtualenv on your distro.  Follow the appropriate
instructions below.

#### Mainline build (Debian-based container build)

From the root directory of the checked out repository, run

    make binary

This builds `calicoctl` command line tool in the `dist/` directory.

#### Virtual environment build

Setup a virtualenv using the following makefile target:

    make setup-env

Build `calicoctl` with `pyinstaller`.

    pyinstaller calico_containers/calicoctl.py -a -F -s --clean

This builds `calicoctl` command line tool in the `dist/` directory.


## The Calico Docker test suites and test environment

There are two test suites used to validate Calico Docker function - unit tests and system tests.  In addition to the
tests, there are makefile targets to spin up an instance of etcd  - useful for test deployments.

If you are developing Calico Docker code that you would like to contribute upstream, please ensure at a minimum that
the unit tests and system tests successfully run, and, preferably, ensure new functionality is unit tested and system
tested where necessary.  We aim to keep improving our total code and path coverage with each check-in.

### Spinning up an instance of etcd

The supplied Makefile includes targets for spinning up a single instance of and etcd server.  This
is useful if you want to do any local testing.

From the root directory of the checked out repository, run

    make run-etcd


This starts an etcd bound to a local IP address (automatically determined).  If you have multiple local IP
addresses and wish to explicitly select an IP address to bind to, set the environment variable LOCAL_IP_ENV with the
correct IP address.  For example:

    LOCAL_IP_ENV=192.168.0.23 make run-etcd

If you are using the system test makefile target to run the system test, it automatically spins up an instance of 
etcd so it is not necessary to explicitly run these commands.

### Running the unit tests

The Calico Docker unit tests provide code and path coverage of a number of the integration
and plugin modules, and some of the calicoctl command line tool processing.

From the root directory of the checked out repository, run

    make ut

The unit test output provides a breakdown of test run and code coverage across the various modules.

The unit tests are written using the nose and unittest framework.  The test files are located in ```tests/unit```.

### Running the system tests

The Calico Docker system tests provide detailed testing of the `calicoctl` command line tool and the `calico/node`
container image.  The tests cover multiple topologies and covers most of the available `calicoctl` command line
options.

The full suite of system tests takes approximately 30 minutes to complete. 
If you are developing code for Calico Docker and are regularly running
the system tests, you can run a [subset of the tests](./Building.md#running-a-subset-of-system-tests) instead.

Both STs start an etcd server bound to a local IP address (automatically determined).  If you have
multiple local IP addresses and wish to explicitly select an IP address to bind to, set the environment variable
LOCAL_IP_ENV with the correct IP address.  For example:

    sudo LOCAL_IP_ENV=192.168.0.23 make st

The STs require root access to run, so run them with sudo.

The STs require a number of Python packages to be installed.  You can install these using

    pip install -r calicoctl/requirements.txt

#### The full ST suite

From the root directory of the checked out repository, run

    sudo make st

The full ST suite builds the calicoctl binary and calico/node docker image.  It starts a container running etcd, and then runs all of the tests defined in tests/st, using the built calicoctl and calico/node to run the tests.

#### Running a subset of system tests

If you wish to test a single system test module (particularly useful when writing a new system test, or running a
quick sanity check), use the ST make target with an environment variable ST_TO_RUN set to the path of the module
to run, or a directory containing a set of modules to run.  For example:

To run all of the BGP tests:

    sudo ST_TO_RUN=tests/st/bgp make st

To run the single no-orchestrator, mainline multi-host test:

    sudo ST_TO_RUN=tests/st/no_orchestrator/test_mainline_multi_host.py make st

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/Building.md?pixel)](https://github.com/igrigorik/ga-beacon)
