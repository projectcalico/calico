---
title: Release notes
canonical_url: '/release-notes/'
---

The following table shows component versioning for {{site.prodname}}  **{{ page.version }}**.

To select a different version, click **Releases** in the top navigation bar.

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
|------------------------|---------|
{% for component in release.components %}
{%- capture component_name %}{{ component[0] }}{% endcapture -%}
| {{ component_name }}   | [{{ component[1].version }}]({% include component_url component=component_name release=release %}) |
{% endfor %}

{% endfor %}
