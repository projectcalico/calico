---
title: Release notes
description: What's new, and why features provide value for upgrading.
canonical_url: '/release-notes/index'
---

The following table shows component versioning for {{site.prodname}}  **{{ page.version }}**.

To select a different version, click **Releases** in the top navigation bar.

{% for release in site.data.versions %}
## {{ release.title }}
{% unless release.title == "master" %}
[Release archive](https://github.com/projectcalico/calico/releases/download/{{ release.title }}/release-{{ release.title }}.tgz){:target="_blank"} with Kubernetes manifests, Docker images and binaries.
{% endunless %}

{% if release.note %}
{{ release.note }}
{% else %}
{% include release-notes/{{release.title}}-release-notes.md %}
{% endif %}

| Component              | Version |
|------------------------|---------|
{% for component in release.components %}
{%- capture component_name %}{{ component[0] }}{% endcapture -%}

{%- comment -%}Use the imageName for the component, if it has one, for better readability{%- endcomment -%}
{%- if page.imageNames[component_name] -%}
    {%- assign component_name = page.imageNames[component_name] -%}
{%- endif -%}

| {{ component_name }}   | [{{ component[1].version }}]({% include component_url component=component_name release=release %}) |
{% endfor %}

{% endfor %}
