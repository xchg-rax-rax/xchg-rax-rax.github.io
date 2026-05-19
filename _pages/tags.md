---
layout: page
permalink: /tags/
title: "tags"
---

{% assign tags = site.tags | sort %}

{% for tag in tags %}
<h2 id="{{ tag[0] | slugify }}"><code>#{{ tag[0] }}</code></h2>
<ul>
  {% for post in tag[1] %}
    <li>
      <code>{{ post.date | date: "%Y-%m-%d" }}</code>
      &nbsp;
      <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
    </li>
  {% endfor %}
</ul>
{% endfor %}
