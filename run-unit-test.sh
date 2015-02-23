#!/bin/bash

# Shell script for running the Calico unit test suite.
#
# Invoke as './run-unit-test.sh'. Environment variable NOSETEST_ARGS
# may be used to pass additional arguments to nosetests.  For example:
#
# NOSETEST_ARGS="--nocapture calico.openstack.test.test_plugin:TestPlugin" ./run-unit-test.sh
#
# to run a specific test file, and show the output from it even if it
# passes.

#rm -rf env
virtualenv env
. env/bin/activate
pip install -e .
pip install nose mock coverage
nosetests --with-coverage --cover-erase $NOSETEST_ARGS
coverage html
