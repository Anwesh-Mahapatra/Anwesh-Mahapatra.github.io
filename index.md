---
layout: default
---

# /var/log/anwesh
Core Dumps, Malware Analysis, and Raw Notes.

## Logs

{% assign series_groups = site.posts | group_by: "series" %}
{% for group in series_groups %}
  {% if group.name %}
### {{ group.name }}
<ul>
  {% assign parts = group.items | sort: "part" %}
  {% for post in parts %}
    <li>
      <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
      <span style="font-size: small; color: #777;">- {{ post.date | date: "%B %d, %Y" }}</span>
    </li>
  {% endfor %}
</ul>
  {% endif %}
{% endfor %}

{% assign standalone = site.posts | where_exp: "post", "post.series == nil" %}
{% if standalone.size > 0 %}
### Standalone
<ul>
  {% for post in standalone %}
    <li>
      <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
      <span style="font-size: small; color: #777;">- {{ post.date | date: "%B %d, %Y" }}</span>
    </li>
  {% endfor %}
</ul>
{% endif %}