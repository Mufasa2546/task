/* Task visit counter. No cookies, nothing personal stored. Add to a site's <head>:
   <script defer src="https://task.brandbridgeacademy.workers.dev/t.js"></script> */
(function () {
  var me = document.currentScript, api = (me && me.src ? new URL(me.src).origin : "https://task.brandbridgeacademy.workers.dev") + "/api/hit";
  var h = location.hostname, first = true, last = null;
  if (!h || /^(localhost|127\.|10\.|192\.168\.)|\.local$/.test(h) || location.protocol === "file:") return;
  // Opening the site once with ?task_ignore=1 stops counting that browser (?task_ignore=0 undoes it).
  try {
    var q = /[?&]task_ignore=([01])/.exec(location.search);
    if (q) q[1] === "1" ? localStorage.setItem("task_ignore", "1") : localStorage.removeItem("task_ignore");
    if (localStorage.getItem("task_ignore") === "1") return;
  } catch (e) {}
  function send() {
    var p = location.pathname;
    if (p === last) return;
    last = p;
    var d = JSON.stringify({ h: h, p: p, r: first ? document.referrer : "", w: window.innerWidth });
    first = false;
    try { if (navigator.sendBeacon && navigator.sendBeacon(api, d)) return; } catch (e) {}
    try { fetch(api, { method: "POST", body: d, keepalive: true, mode: "no-cors" }); } catch (e) {}
  }
  // Single-page sites change the URL without reloading, so count those page changes too.
  var push = history.pushState;
  history.pushState = function () { var r = push.apply(this, arguments); setTimeout(send, 0); return r; };
  addEventListener("popstate", function () { setTimeout(send, 0); });
  if (document.visibilityState === "prerender") document.addEventListener("visibilitychange", function v() { if (document.visibilityState !== "prerender") { document.removeEventListener("visibilitychange", v); send(); } });
  else send();
})();
