---
title: Get started
description: Resources to get started.
canonical_url: '/about/index'
show_read_time: false
show_toc: false
---

{{ page.description }}

{% capture content %}{% include index.html %}{% endcapture %}
{{ content | replace: "    ", "" }}
