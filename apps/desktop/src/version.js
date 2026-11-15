/**
 * Version of the desktop shell.
 *
 * Kept as a module rather than read from package.json so the browser does not
 * need a JSON fetch for one string; `test/version.test.mjs` asserts it matches
 * package.json and the Tauri manifest so the three cannot drift.
 */
export const APP_VERSION = "0.1.0";

/** Licence of the project, shown in the about block. */
export const APP_LICENSE = "GPL-3.0-only";
