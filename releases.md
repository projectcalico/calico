---
title: Project Calico Documentation Archives
description: Home
layout: docwithnav
---
This page contains permalinks to specific versions of Project Calico documentation, as well as links to the latest released
and the nightly build of documentation. Each set of versioned docs includes a Release Nodes page for that particular
version.
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
