---
title: Project Calico Documentation Archives
description: Home
layout: docwithnav
---
{%- if site.archive %}
- [{{site.data.versions.first.title}} (latest)](/)
- [nightly](/master/){: data-proofer-ignore=""}
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
