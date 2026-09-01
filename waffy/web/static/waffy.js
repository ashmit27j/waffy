/* waffy Control Panel — waffy.js
   Minimal JS: auto-refresh for events/dashboard pages.
*/

(function () {
  "use strict";

  var AUTO_REFRESH_PAGES = ["/panel", "/panel/", "/panel/events"];
  var AUTO_REFRESH_INTERVAL_MS = 30000; // 30 seconds

  var currentPath = window.location.pathname;

  if (AUTO_REFRESH_PAGES.indexOf(currentPath) !== -1) {
    setTimeout(function () {
      location.reload();
    }, AUTO_REFRESH_INTERVAL_MS);
  }
})();
