---
title: Project Calico Documentation Archives
description: Home
layout: docwithnav
---
{% if site.archive %}
- [latest](/)
- [nightly](/master)
{%- for version in site.data.archives -%}
{%- if version.first -%}
    {%- for v in version["legacy"] %}
- [{{ v }}](/{{ v }})
    {%- endfor -%}
{% else %}
- [{{ version }}](/{{ version }})
{% endif -%}
{%- endfor -%}
{% endif %}
