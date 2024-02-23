#!/usr/bin/env python3

import shutil
from functools import cache

import pytest
import requests
import rich.progress
import yaml

import variables

HELM_CHART = "https://projectcalico.docs.tigera.io/charts/index.yaml"

def skip_if_master(reason):
    return pytest.mark.skipif(variables.RELEASE_STREAM == "master", reason=reason)

class ResponseMissingContentDispositionError(Exception):
    pass

def get_filename_from_url(url):
    url_path = urllib.parse.urlparse(url).path
    filename = pathlib.Path(url_path).name
    return filename


def get_content_disposition(response):
    filename = response.headers["Content-Disposition"].replace(
        "attachment; filename=", ""
    )
    return filename


def download_url_to_file(url, destination):
    response = requests.get(url, stream=True)
    length = int(response.headers["Content-Length"])
    filename = get_content_disposition(response)
    with rich.progress.wrap_file(
        response.raw, total=length, description=filename
    ) as infile:
        with open(destination, "wb") as outfile:
            shutil.copyfileobj(infile, outfile)


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
