(function () {
  // 页面的根：整页里是 .wrap，博客里它套在 .sl 里面；只在它底下找，不碰博客别处的东西
  var root = document.querySelector('[data-sl-root]') || document.body;

  // ---- 两页：方案、更新日志 ----
  var tablist = root.querySelector('[role="tablist"][data-tabs]');
  var tabs = tablist ? Array.prototype.slice.call(tablist.querySelectorAll('[role="tab"]')) : [];
  var panelOf = function (tab) { return document.getElementById(tab.getAttribute('aria-controls')); };
  tabs = tabs.filter(function (t) { return !!panelOf(t); });
  if (tabs.length > 1) {
    var tabFor = function (el) {
      for (var i = 0; i < tabs.length; i++) {
        var p = panelOf(tabs[i]);
        if (p === el || p.contains(el)) { return tabs[i]; }
      }
      return null;
    };
    // 选一页；回 true 表示真有一页显示或藏起来了（这时浏览器自己滚的位置可能不对）
    var select = function (tab) {
      var changed = false;
      tabs.forEach(function (t) {
        var on = t === tab;
        var p = panelOf(t);
        if (p.hidden === on) { changed = true; }
        p.hidden = !on;
        t.setAttribute('aria-selected', String(on));
        t.setAttribute('tabindex', on ? '0' : '-1');
      });
      return changed;
    };
    var targetOf = function (hash) {
      if (!hash || hash.length < 2) { return null; }
      var id = hash.slice(1);
      try { id = decodeURIComponent(id); } catch (e) {}
      var el = document.getElementById(id);
      return el && root.contains(el) ? el : null;
    };
    // 换页时把地址栏改成这一页的（不添历史记录）：更新日志是 #progress；方案那一页地址里已经指着它里面某处就不动，否则去掉 #
    var setHash = function (tab) {
      if (!window.history || !history.replaceState) { return; }
      var cur = targetOf(location.hash);
      if (cur && tabFor(cur) === tab) { return; }
      if (!cur && location.hash && location.hash.length > 1) { return; }   // 指着页外的东西，不碰
      var url = tab === tabs[0] ? location.pathname + location.search : '#' + panelOf(tab).id;
      if (url === location.pathname + location.search && !location.hash) { return; }
      try { history.replaceState(history.state, '', url); } catch (e) {}
    };
    // 跟着地址里的 # 换页：目标在藏着的那一页里，就先换页，再滚到目标。
    // # 指着两页以外的东西（页头、博客别处）：打开时照样开方案那一页（总要有一页是选中的），之后不动
    var follow = function (scroll, init) {
      var hash = location.hash || '';
      var el = targetOf(hash);
      var tab = el ? tabFor(el) : null;
      if (!tab) {
        if (!init && hash.length > 1) { return; }
        var other = null;
        if (hash.length > 1) { try { other = document.getElementById(decodeURIComponent(hash.slice(1))); } catch (e) {} }
        if (select(tabs[0]) && scroll && other) { other.scrollIntoView(); }
        return;
      }
      if (select(tab) && scroll) { el.scrollIntoView(); }
    };

    tabs.forEach(function (tab) {
      var p = panelOf(tab);
      p.setAttribute('role', 'tabpanel');
      p.setAttribute('aria-labelledby', tab.id);
      p.setAttribute('tabindex', '0');
      tab.addEventListener('click', function () { select(tab); setHash(tab); });
    });
    tablist.addEventListener('keydown', function (e) {
      var i = tabs.indexOf(document.activeElement);
      if (i < 0) { return; }
      var n = -1;
      if (e.key === 'ArrowRight') { n = (i + 1) % tabs.length; }
      else if (e.key === 'ArrowLeft') { n = (i - 1 + tabs.length) % tabs.length; }
      else if (e.key === 'Home') { n = 0; }
      else if (e.key === 'End') { n = tabs.length - 1; }
      if (n < 0) { return; }
      e.preventDefault();
      select(tabs[n]);
      tabs[n].focus();
      setHash(tabs[n]);
    });
    // 页里指向另一页的链接（目录里的那些）：点下去先换页，浏览器再照常滚过去。
    // 用捕获：博客主题在每个 # 链接上自己挂了平滑滚动（先于冒泡到这里），它量位置时目标那一页要已经显示出来
    root.addEventListener('click', function (e) {
      var a = e.target && e.target.closest ? e.target.closest('a[href^="#"]') : null;
      if (!a) { return; }
      var el = targetOf(a.getAttribute('href'));
      var tab = el ? tabFor(el) : null;
      if (tab) { select(tab); }
    }, true);
    // 前进、后退
    window.addEventListener('hashchange', function () { follow(true); });
    window.addEventListener('popstate', function () { follow(true); });

    tablist.hidden = false;
    // 打开时：地址指着更新日志（#progress）就开那一页，滚过去；没有 #、指着方案里某处或两页以外，开方案那一页
    follow(true, true);
  }

  // ---- 看一轮怎么走 ----
  var fig = root.querySelector('.pathfig');
  if (fig) {
    var btns = Array.prototype.slice.call(fig.querySelectorAll('[data-path-btn]'));
    var panels = Array.prototype.slice.call(fig.querySelectorAll('[data-for]'));
    var svg = fig.querySelector('svg[data-label-now]');
    var labelAll = svg ? svg.getAttribute('aria-label') : '';
    var setPath = function (p) {
      fig.setAttribute('data-path', p);
      btns.forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-path-btn') === p)); });
      panels.forEach(function (el) { el.hidden = el.getAttribute('data-for') !== p; });
      // 「目前已经实现」那一看法，读屏读到的说明换成哪些上了、哪些只上了一半、哪些灰掉
      if (svg) { svg.setAttribute('aria-label', p === 'now' ? svg.getAttribute('data-label-now') : labelAll); }
    };
    btns.forEach(function (b) {
      b.addEventListener('click', function () { setPath(b.getAttribute('data-path-btn')); });
    });
    setPath('all');
  }

  var tip = null;
  var showTip = function (row, x, y) {
    if (!tip) { tip = document.createElement('div'); tip.className = 'sl-tip'; tip.setAttribute('role', 'tooltip'); document.body.appendChild(tip); }
    tip.textContent = '';
    var b = document.createElement('b');
    b.textContent = row.getAttribute('data-tip-title') || '';
    tip.appendChild(b);
    tip.appendChild(document.createTextNode(row.getAttribute('data-tip') || ''));
    tip.hidden = false;
    var w = tip.offsetWidth, h = tip.offsetHeight;
    var vw = document.documentElement.clientWidth, vh = document.documentElement.clientHeight;
    var left = Math.min(Math.max(8, x + 12), vw - w - 8);
    var top = y + 16;
    if (top + h > vh - 8) { top = Math.max(8, y - h - 12); }
    tip.style.left = left + 'px';
    tip.style.top = top + 'px';
  };
  var hideTip = function () { if (tip) { tip.hidden = true; } };
  Array.prototype.slice.call(root.querySelectorAll('.bar-row[data-tip]')).forEach(function (row) {
    row.addEventListener('mousemove', function (e) { showTip(row, e.clientX, e.clientY); });
    row.addEventListener('mouseleave', hideTip);
    row.addEventListener('focus', function () {
      var r = row.getBoundingClientRect();
      showTip(row, r.left + 24, r.bottom - 8);
    });
    row.addEventListener('blur', hideTip);
  });
  window.addEventListener('scroll', hideTip, { passive: true });
})();
