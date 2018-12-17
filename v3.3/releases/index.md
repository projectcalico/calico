---
title: Releases
canonical_url: https://docs.projectcalico.org/v3.4/releases/
---

The following table shows component versioning for Calico  **{{ page.version }}**.

Use the version selector at the top-right of this page to view a different release.

{% for release in site.data.versions[page.version] %}
## {{ release.title }}
{% unless release.title == "master" %}
[Release archive](https://github.com/projectcalico/calico/releases/download/{{ release.title }}/release-{{ release.title }}.tgz) with Kubernetes manifests, Docker images and binaries.
{% endunless %}

{% if release.note %}
{{ release.note }}
{% else %}
{% include {{page.version}}/release-notes/{{release.title}}-release-notes.md %}
{% endif %}

| Component              | Version |
|------------------------|---------|{% for component_name in release.components %}
| {{ component_name[0] }}   | [{{ component_name[1].version }}]({{ component_name[1].url }}) |{% endfor %}

{% endfor %}
