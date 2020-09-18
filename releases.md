---
title: Project Calico Documentation Archives
description: Home
layout: docwithnav
---
This page contains permalinks to all Project Calico documentation for specific
versions, as well as to the latest (always the most recently released version) and the nightly build of
documentation. Each set of versioned docs includes a Release Nodes
page for that particular version.
{%- if site.archive %}
- [latest](/) (currently {{site.data.versions.first.title}})
- [nightly](/master/){: data-proofer-ignore=""} (master)
- [{{site.data.versions.first.title}}](/archive/{{page.version}})
{%- for version in site.data.archives %}
{%- if version.first %}
    {%- for v in version["legacy"] %}
- [{{ v }}](/archive/{{ v }}/){: data-proofer-ignore=""}
    {%- endfor %}
{%- else %}
- [{{ version }}](/archive/{{ version }}/)
{%- endif %}
{%- endfor %}
{% endif %}
