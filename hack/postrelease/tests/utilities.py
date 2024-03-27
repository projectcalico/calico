#!/usr/bin/env python3

import shutil
from functools import cache

import pytest
import requests
import yaml

import variables

HELM_CHART = "https://projectcalico.docs.tigera.io/charts/index.yaml"

def skip_if_master(reason):
    return pytest.mark.skipif(variables.RELEASE_STREAM == "master", reason=reason)

class FailedDownloadError(Exception):
    pass

def download_url_to_file(url, destination):
    response = requests.get(url, stream=True)
    if response.status_code != 200:
        raise FailedDownloadError(f"HTTP error {response.status_code}")
    with open(destination, "wb") as outfile:
        shutil.copyfileobj(response.raw, outfile)


def download_url_to_file_noprogress(url, destination):
    response = requests.get(url, stream=True)
    with open(destination, "wb") as outfile:
        shutil.copyfileobj(response.raw, outfile)


def tarfile_members_to_map(tf):
    members = tf.getmembers()
    file_map = {
        member.get_info()["name"]: member
        for member in members
        if not member.get_info()["name"].endswith("/")
    }
    return file_map


@cache
def get_helm_chart():
    response = requests.get(HELM_CHART)
    assert response.status_code == 200, "Could not get helm chart index"
    index = yaml.safe_load(response.text)
    return index
