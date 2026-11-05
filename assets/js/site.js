(function () {
  var root = document.documentElement;

  // Theme switch: remembers the reader's choice when storage is available.
  var toggle = document.querySelector(".theme-toggle");
  function currentTheme() {
    var set = root.getAttribute("data-theme");
    if (set) return set;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  // Keep the phone's browser bar the same colour as the page.
  function syncThemeColor() {
    var bg = getComputedStyle(document.body).backgroundColor;
    document.querySelectorAll('meta[name="theme-color"]').forEach(function (m) { m.setAttribute("content", bg); });
  }
  if (toggle) {
    toggle.addEventListener("click", function () {
      var next = currentTheme() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("theme", next); } catch (e) {}
      syncThemeColor();
    });
  }
  if (root.hasAttribute("data-theme")) syncThemeColor();

  // Scroll-driven extras, all updated in one animation frame per scroll:
  // the header tucks away while reading down and comes back on the way up,
  // a thin bar shows reading progress on posts, and a back-to-top button
  // appears once the reader is well into a long page.
  var header = document.querySelector(".site-header");
  var progress = document.querySelector(".progress");
  var toTop = document.querySelector(".to-top");
  var article = document.querySelector(".post");
  var lastY = window.scrollY, ticking = false;
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (toTop) toTop.hidden = false;

  function onScroll() {
    ticking = false;
    var y = window.scrollY;
    var dy = y - lastY;
    if (header) {
      header.classList.toggle("is-scrolled", y > 4);
      var busy = document.body.style.overflow === "hidden" || header.contains(document.activeElement);
      if (y < 80 || busy) header.classList.remove("is-hidden");
      else if (dy > 6) header.classList.add("is-hidden");
      else if (dy < -6) header.classList.remove("is-hidden");
    }
    if (progress) {
      var p = 0;
      if (article) {
        var r = article.getBoundingClientRect();
        var span = r.height - window.innerHeight;
        p = span > 0 ? Math.min(1, Math.max(0, -r.top / span)) : 1;
      }
      progress.style.transform = "scaleX(" + p + ")";
    }
    if (toTop) toTop.classList.toggle("is-visible", y > window.innerHeight * 1.5);
    lastY = y;
  }
  window.addEventListener("scroll", function () {
    if (!ticking) { ticking = true; requestAnimationFrame(onScroll); }
  }, { passive: true });
  window.addEventListener("resize", onScroll, { passive: true });
  onScroll();
  if (toTop) {
    toTop.addEventListener("click", function () {
      window.scrollTo({ top: 0, behavior: reduce ? "auto" : "smooth" });
      var skip = document.querySelector(".brand");
      if (skip) skip.focus({ preventScroll: true });
    });
  }

  // Copy buttons on code blocks.
  document.querySelectorAll(".post-body pre").forEach(function (pre) {
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-btn";
    btn.textContent = "Copy";
    btn.addEventListener("click", function () {
      var code = pre.querySelector("code") || pre;
      var text = code.innerText;
      var done = function () {
        btn.textContent = "Copied";
        btn.classList.add("is-done");
        setTimeout(function () { btn.textContent = "Copy"; btn.classList.remove("is-done"); }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { btn.textContent = "Select and copy"; });
      } else {
        btn.textContent = "Select and copy";
      }
    });
    pre.parentNode.insertBefore(btn, pre);
    pre.parentNode.classList.add("has-copy");
  });

  // Image zoom: the picture grows out of its place in the post to fill the
  // screen (FLIP: measure First and Last position, Invert, Play), then
  // shrinks back on close. Works in every modern browser via the Web
  // Animations API; reduced-motion readers get a plain fade instead.
  var zoomables = document.querySelectorAll(".post-body img");
  if (zoomables.length && document.body.animate) {
    var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var EASE = "cubic-bezier(0.2, 0.8, 0.2, 1)";
    var open = null;

    var box = document.createElement("div");
    box.className = "lightbox";
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-modal", "true");
    box.setAttribute("aria-label", "Enlarged image");
    box.hidden = true;
    box.innerHTML =
      '<div class="lightbox-backdrop"></div>' +
      '<img class="lightbox-img" alt="">' +
      '<div class="lightbox-bar">' +
        '<p class="lightbox-caption"></p>' +
        '<a class="lightbox-full" target="_blank" rel="noopener">Open full size</a>' +
        '<button type="button" class="lightbox-close" aria-label="Close image">Close <kbd>Esc</kbd></button>' +
      '</div>';
    document.body.appendChild(box);
    var bigImg = box.querySelector(".lightbox-img");
    var backdrop = box.querySelector(".lightbox-backdrop");
    var bar = box.querySelector(".lightbox-bar");
    var caption = box.querySelector(".lightbox-caption");
    var fullLink = box.querySelector(".lightbox-full");
    var closeBtn = box.querySelector(".lightbox-close");

    // Where the enlarged picture should sit: as big as the screen allows,
    // never larger than its real pixel size, centred above the caption bar.
    function targetRect(img) {
      var vw = window.innerWidth, vh = window.innerHeight;
      var pad = vw < 600 ? 12 : 40;
      var barH = bar.offsetHeight || 56;
      var nw = img.naturalWidth || img.width, nh = img.naturalHeight || img.height;
      var scale = Math.min((vw - pad * 2) / nw, (vh - pad * 2 - barH) / nh, 1);
      var w = nw * scale, h = nh * scale;
      return { left: (vw - w) / 2, top: Math.max(pad, (vh - barH - h) / 2), width: w, height: h };
    }

    // Transform that makes the enlarged picture look exactly like the small one.
    function invert(from, to) {
      return "translate(" + (from.left - to.left) + "px," + (from.top - to.top) + "px) scale(" +
        (from.width / to.width) + "," + (from.height / to.height) + ")";
    }

    function lockScroll(on) {
      var gap = window.innerWidth - document.documentElement.clientWidth;
      document.body.style.overflow = on ? "hidden" : "";
      document.body.style.paddingRight = on && gap > 0 ? gap + "px" : "";
    }

    function show(img) {
      if (open) return;
      open = img;
      var capEl = img.nextElementSibling && img.nextElementSibling.tagName === "EM" ? img.nextElementSibling : null;
      caption.textContent = capEl ? capEl.textContent : (img.alt || "");
      fullLink.href = img.currentSrc || img.src;
      bigImg.src = img.currentSrc || img.src;
      bigImg.alt = img.alt;

      box.hidden = false;
      lockScroll(true);
      var to = targetRect(img);
      bigImg.style.left = to.left + "px";
      bigImg.style.top = to.top + "px";
      bigImg.style.width = to.width + "px";
      bigImg.style.height = to.height + "px";
      img.style.visibility = "hidden";
      closeBtn.focus({ preventScroll: true });

      var fade = { duration: reduceMotion ? 150 : 320, easing: "ease-out", fill: "both" };
      backdrop.animate([{ opacity: 0 }, { opacity: 1 }], fade);
      bar.animate([{ opacity: 0, transform: "translateY(8px)" }, { opacity: 1, transform: "none" }],
        { duration: reduceMotion ? 150 : 300, delay: reduceMotion ? 0 : 140, easing: "ease-out", fill: "both" });
      if (reduceMotion) {
        bigImg.animate([{ opacity: 0 }, { opacity: 1 }], fade);
      } else {
        bigImg.animate([{ transform: invert(img.getBoundingClientRect(), to) }, { transform: "none" }],
          { duration: 460, easing: EASE, fill: "both" });
      }
    }

    function hide() {
      if (!open) return;
      var img = open;
      open = null;
      var from = img.getBoundingClientRect();
      var to = bigImg.getBoundingClientRect();
      var fade = { duration: reduceMotion ? 120 : 260, easing: "ease-in", fill: "both" };
      backdrop.animate([{ opacity: 1 }, { opacity: 0 }], fade);
      bar.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 140, fill: "both" });
      var done = function () {
        box.hidden = true;
        img.style.visibility = "";
        lockScroll(false);
        [bigImg, backdrop, bar].forEach(function (el) {
          el.getAnimations().forEach(function (a) { a.cancel(); });
        });
        img.focus({ preventScroll: true });
      };
      var anim = reduceMotion
        ? bigImg.animate([{ opacity: 1 }, { opacity: 0 }], fade)
        : bigImg.animate([{ transform: "none" }, { transform: invert(from, to) }],
            { duration: 380, easing: EASE, fill: "both" });
      anim.onfinish = done;
    }

    zoomables.forEach(function (img) {
      img.classList.add("zoomable");
      img.setAttribute("tabindex", "0");
      img.setAttribute("role", "button");
      img.setAttribute("aria-label", "Enlarge image: " + (img.alt || "screenshot"));
      img.addEventListener("click", function () { show(img); });
      img.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); show(img); }
      });
    });
    // On phones: drag the picture down to dismiss it, like a photo app.
    var drag = null;
    bigImg.addEventListener("pointerdown", function (e) {
      if (e.pointerType === "mouse" || !open) return;
      drag = { y: e.clientY, dy: 0, id: e.pointerId };
      bigImg.setPointerCapture(e.pointerId);
    });
    bigImg.addEventListener("pointermove", function (e) {
      if (!drag || e.pointerId !== drag.id) return;
      drag.dy = Math.max(0, e.clientY - drag.y);
      bigImg.style.transform = "translateY(" + drag.dy + "px)";
      backdrop.style.opacity = String(Math.max(0.25, 1 - drag.dy / 400));
    });
    function endDrag(e) {
      if (!drag || e.pointerId !== drag.id) return;
      var dy = drag.dy; drag = null;
      backdrop.style.opacity = "";
      if (dy > 90) {
        dragDismiss(dy);
      } else {
        bigImg.style.transform = "";
        if (dy > 4) bigImg.animate([{ transform: "translateY(" + dy + "px)" }, { transform: "none" }],
          { duration: 220, easing: EASE });
        else hide();
      }
    }
    bigImg.addEventListener("pointerup", endDrag);
    bigImg.addEventListener("pointercancel", endDrag);

    function dragDismiss(dy) {
      if (!open) return;
      var img = open; open = null;
      bar.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 140, fill: "both" });
      backdrop.animate([{ opacity: 0.7 }, { opacity: 0 }], { duration: 220, easing: "ease-in", fill: "both" });
      bigImg.style.transform = "";
      var a = bigImg.animate(
        [{ transform: "translateY(" + dy + "px)", opacity: 1 }, { transform: "translateY(" + (dy + 120) + "px)", opacity: 0 }],
        { duration: 220, easing: "ease-in", fill: "both" });
      a.onfinish = function () {
        box.hidden = true;
        img.style.visibility = "";
        lockScroll(false);
        [bigImg, backdrop, bar].forEach(function (el) {
          el.getAnimations().forEach(function (an) { an.cancel(); });
        });
        img.focus({ preventScroll: true });
      };
    }

    backdrop.addEventListener("click", hide);
    bigImg.addEventListener("click", function (e) {
      // touch taps are handled by the drag logic above
      if (e.pointerType && e.pointerType !== "mouse") return;
      hide();
    });
    closeBtn.addEventListener("click", hide);
    document.addEventListener("keydown", function (e) {
      if (!open) return;
      if (e.key === "Escape") { e.preventDefault(); hide(); }
      if (e.key === "Tab") {
        // keep focus inside the dialog
        var items = [fullLink, closeBtn];
        var i = items.indexOf(document.activeElement);
        e.preventDefault();
        items[(i + (e.shiftKey ? items.length - 1 : 1)) % items.length].focus();
      }
    });
    window.addEventListener("resize", function () {
      if (!open) return;
      var to = targetRect(open);
      bigImg.style.left = to.left + "px"; bigImg.style.top = to.top + "px";
      bigImg.style.width = to.width + "px"; bigImg.style.height = to.height + "px";
    });
  }

  // Link icons on section headings, so a section can be shared directly.
  document.querySelectorAll(".post-body h2[id], .post-body h3[id]").forEach(function (h) {
    var a = document.createElement("a");
    a.className = "heading-link";
    a.href = "#" + h.id;
    a.setAttribute("aria-label", "Link to this section");
    a.textContent = "#";
    h.appendChild(a);
  });
})();
