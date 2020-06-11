---
layout: archive
author_profile: true 
title: Categories
permalink: /categories/
---

{% for i in (1..categories_max) reversed %}
  {% for category in site.categories %}
    {% if category[1].size == i %}
          {% for post in category.last %}
            {% include archive-single.html type=page.entries_layout %}
          {% endfor %}
    {% endif %}
  {% endfor %}
{% endfor %}