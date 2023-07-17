#!/usr/bin/env python3

import pytest

import variables


@pytest.fixture(scope="session", autouse=True)
def log_global_env_facts(record_testsuite_property):
    record_testsuite_property("Release Stream", variables.RELEASE_STREAM)
    record_testsuite_property("Release Version", variables.RELEASE_VERSION)
    record_testsuite_property("Flannel Version", variables.FLANNEL_VERSION)
    record_testsuite_property("Operator Version", variables.OPERATOR_VERSION)
