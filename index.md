---
layout: default
---

# Welcome to Nocaptech
Reverse Engineering | Malware Analysis | Rants.

## Logs
<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
      <span style="font-size: small; color: #777;">- {{ post.date | date: "%B %d, %Y" }}</span>
    </li>
  {% endfor %}
</ul>