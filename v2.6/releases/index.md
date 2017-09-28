---
title: Releases
redirect_from: latest/releases/index
---

The following table shows component versioning for Calico  **{{ page.version }}**.

Use the version selector at the top-right of this page to view a different release.

{% for release in site.data.versions[page.version] %}
## {{ release.title }}
{% unless release.title == "master" %}
[Release archive](https://github.com/projectcalico/calico/releases/download/{{ release.title }}/release-{{ release.title }}.tgz) with Kubernetes manifests, Docker images and binaries.
{% endunless %}

{{ release.note }}

| Component              | Version |
|------------------------|---------|{% for component_name in release.components %}
| {{ component_name[0] }}   | [{{ component_name[1].version }}]({{ component_name[1].url }}) |{% endfor %}

{% endfor %}
