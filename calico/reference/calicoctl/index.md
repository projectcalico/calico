---
title: calicoctl
show_read_time: false
description: Optional command line interface (CLI) to manage Calico resources.
show_toc: false
---

{{ page.description }}

The calicoctl CLI tool allows management of {{site.prodname}} API resources, and can be used to perform other administrative tasks for
managing a {{site.prodname}} installation.

You can use kubectl to manage {{site.prodname}} resources instead by [installing the {{site.prodname}} API server]({{site.baseurl}}/maintenance/install-apiserver).

{% capture content %}{% include index.html %}{% endcapture %}
{{ content | replace: "    ", "" }}
