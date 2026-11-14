/**
 * Entry point.
 *
 * Nothing here but the hand-off: find the mount point and start the shell. If
 * the shell itself cannot start, the page gets one line of ASCII text instead of
 * a blank window — this is the only string in `src/` that is not in a language
 * pack, because it is the path taken when the packs could not be read.
 */

import { startApp } from "./app.js";

const root = document.getElementById("app");

if (!root) {
  document.body.textContent = "MelonARC: mount point missing";
} else {
  startApp(root).catch((error) => {
    console.error(error);
    root.textContent = "MelonARC: the interface could not start. See the console for details.";
  });
}
