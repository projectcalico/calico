---
title: Self-managed on-premises
description: Install both Calico networking and network policy for the most flexibility for on-premises deployments.  
show_read_time: false
show_toc: false
---

{{ page.description }}

Calico can be configured to provide newtworking for just Kuberenetes, or to integrate with other infrastructure or
on-premises cloud services.

{% capture content %}{% include index.html %}{% endcapture %}
{{ content | replace: "    ", "" }}
