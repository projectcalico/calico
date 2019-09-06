---
title: Release notes
canonical_url: 'https://docs.projectcalico.org/v3.7/release-notes/index'
---

The following table shows component versioning for {{site.prodname}}  **{{ page.version }}**.

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
|------------------------|---------|
{% for component in release.components %}
{%- capture component_name %}{{ component[0] }}{% endcapture -%}

{%- comment -%}Use the imageName for the component, if it has one, for better readability{%- endcomment -%}
{%- if page.imageNames[component_name] -%}
    {%- assign component_name = site.imageNames[component_name] -%}
{%- endif -%}

| {{ component_name }}   | [{{ component[1].version }}]({% include component_url component=component_name release=release %}) |
{% endfor %}

{% endfor %}
