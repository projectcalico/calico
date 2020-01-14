---
title: Policy for extreme traffic
description: Calico network policy early in the Linux packet processing pipeline to avoid DoS attacks, and selectively bypass Linux conntrack for extremely large number of connections.
show_read_time: false
show_toc: false
---

{{ page.description }}

{% capture content %}{% include index.html %}{% endcapture %}
{{ content | replace: "    ", "" }}
