#!/bin/bash

# Shell script for running the Calico unit test suite.
#
# Invoke as './run-unit-test.sh'. Arguments to this script are passed directly
# to tox: e.g., to force a rebuild of tox's virtual environments, invoke this
# script as './run-unit-test.sh -r'.

coverage erase
tox "$@"
coverage html
