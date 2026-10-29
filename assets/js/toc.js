(function () {
  "use strict";

  function build() {
    var container = document.getElementById("toc");
    if (!container) return;
    var rootList = container.querySelector("ul");
    var headings = document.querySelectorAll(
      ".post-content h1, .post-content h2, .post-content h3, .post-content h4"
    );
    if (!headings.length) {
      container.style.display = "none";
      return;
    }

    // Stack-based nesting: each heading nests under the nearest preceding
    // heading of a strictly lower level, regardless of which tag levels a
    // given post actually uses (posts vary between h1/h2/h3 for sections).
    var stack = [{ level: 0, list: rootList }];

    headings.forEach(function (heading) {
      if (!heading.id) return;
      var level = parseInt(heading.tagName.substring(1), 10);

      while (stack.length > 1 && stack[stack.length - 1].level >= level) {
        stack.pop();
      }

      var parent = stack[stack.length - 1];
      var li = document.createElement("li");
      var a = document.createElement("a");
      a.href = "#" + heading.id;
      a.textContent = heading.textContent;
      li.appendChild(a);
      parent.list.appendChild(li);

      var subList = document.createElement("ul");
      li.appendChild(subList);
      stack.push({ level: level, list: subList });
    });

    // Remove empty trailing sublists left behind by leaf headings.
    container.querySelectorAll("ul").forEach(function (ul) {
      if (!ul.children.length) ul.remove();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", build);
  } else {
    build();
  }
})();
