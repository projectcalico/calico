---
title: Releases
---

The following table shows component versioning for Calico  **{{ page.version }}**.

Use the version selector at the top-right of this page to view a different release.

{% for release in site.data.versions[page.version] %}
## {{ release.title }}

{{ release.note }}

| Component              | Version |
|------------------------|---------|{% for component in release.components %}
| {{ component.name }}   | [{{ component.version }}]({{ component.url }}) |{% endfor %}

{% endfor %}
