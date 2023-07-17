import pytest
import requests

import utilities
import variables

CHART_URL = (
    "https://github.com/projectcalico/calico/releases/download/"
    f"{variables.RELEASE_VERSION}/tigera-operator-{variables.RELEASE_VERSION}.tgz"
)


@pytest.fixture(scope="session")
def operator_helm_chart_entry():
    index = utilities.get_helm_chart()
    entries = [
        e
        for e in index["entries"]["tigera-operator"]
        if e["appVersion"] == variables.RELEASE_VERSION
    ]
    assert entries, "Could not find this release in helm index"
    return entries[0]


@pytest.mark.helm
def test_calico_helm_version(operator_helm_chart_entry):
    # Ensure the version that we found is correct (each entry has 'version' and 'appVersion')
    entry_version = operator_helm_chart_entry["version"]
    assert (
        entry_version == variables.RELEASE_VERSION
    ), f"Chart version ({entry_version}) incorrect in helm index"


@pytest.mark.helm
def test_calico_chart_url(operator_helm_chart_entry):
    # Validate that the URL we got is the URL we expect
    entry_chart_url = operator_helm_chart_entry["urls"][0]
    assert (
        entry_chart_url == CHART_URL
    ), f"Chart URL (entry_chart_url) incorrect in helm index"


@pytest.mark.helm
@pytest.mark.github
def test_calico_operator_url_exists(operator_helm_chart_entry):
    # Validate that the URL is actually active
    response = requests.head(operator_helm_chart_entry["urls"][0], allow_redirects=True)
    assert (
        response.status_code == 200
    ), f"Chart URL returned HTTP {response.status_code}"
