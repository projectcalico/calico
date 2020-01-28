---
title: Project Calico Documentation Archives
description: Home
layout: docwithnav
---
{% if site.archive %}
- [{{site.data.versions.first.title}} (latest)](/)
- [nightly](/master)
{%- for version in site.data.archives -%}
{%- if version.first -%}
    {%- for v in version["legacy"] %}
- [{{ v }}]({{ site.url }}/{{ v }})
    {%- endfor -%}
{% else %}
- [{{ version }}]({{ site.url }}/{{ version }})
{% endif -%}
{%- endfor -%}
{% endif %}
