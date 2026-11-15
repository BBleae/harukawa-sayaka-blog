(function () {
  var fig = document.querySelector('.pathfig');
  if (fig) {
    var btns = Array.prototype.slice.call(fig.querySelectorAll('[data-path-btn]'));
    var panels = Array.prototype.slice.call(fig.querySelectorAll('[data-for]'));
    var setPath = function (p) {
      fig.setAttribute('data-path', p);
      btns.forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-path-btn') === p)); });
      panels.forEach(function (el) { el.hidden = el.getAttribute('data-for') !== p; });
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
  Array.prototype.slice.call(document.querySelectorAll('.bar-row[data-tip]')).forEach(function (row) {
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
