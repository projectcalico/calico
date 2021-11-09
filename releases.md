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
<div id="release-list" class="hidden" markdown="0" data-proofer-ignore>
    <li><a href="/">{% if site.data.versions.first.title == "master" %}nightly{% else %}{{site.data.versions.first.title | regex_replace: site.version_pattern,"Version \1"}}{% endif %}<span class="badge release-badge latest">latest</span></a></li>
    <li role="separator" class="divider"></li>
    <li><a href="/master">nightly<span class="badge release-badge nightly">master</span></a></li>
    {%- for version in site.data.archives %}
        {%- if version.first %}
        {% continue %}
        {%- else %}
        <li><a href="/archive/{{ version }}/">Version {{ version | replace: "v", ""  }}</a></li>
        {%- endif %}
    {%- endfor %}
    <li><a href="/releases">Earlier versions</a></li>
</div>
