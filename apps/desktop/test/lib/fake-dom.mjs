/**
 * A DOM small enough for one smoke test.
 *
 * There is no browser in the development sandbox, and no DOM library can be
 * installed either. This shim implements exactly the surface the shell uses
 * (createElement, attributes, dataset, children, listeners, querySelectorAll)
 * so `startApp` can be mounted in Node and a real navigation can be exercised.
 * It is deliberately not a general purpose DOM: a new browser API used by the
 * app will fail here loudly instead of being silently tolerated.
 */

export class FakeNode {
  /** @param {string} tag */
  constructor(tag) {
    this.tagName = tag;
    this.children = [];
    this.attributes = new Map();
    this.dataset = {};
    this.listeners = new Map();
    this.className = "";
    this.parentNode = null;
    this._text = null;
  }

  get firstChild() {
    return this.children[0] ?? null;
  }

  get textContent() {
    if (this._text !== null) return this._text;
    return this.children.map((child) => child.textContent).join("");
  }

  set textContent(value) {
    this._text = String(value);
    this.children = [];
  }

  /** @param {...any} children */
  append(...children) {
    this._text = null;
    for (const child of children) {
      if (child === null || child === undefined || child === false) continue;
      const node = child instanceof FakeNode || child instanceof FakeText ? child : new FakeText(String(child));
      node.parentNode = this;
      this.children.push(node);
    }
  }

  /** @param {FakeNode | FakeText} child */
  removeChild(child) {
    const index = this.children.indexOf(child);
    if (index >= 0) this.children.splice(index, 1);
  }

  /** @param {string} name @param {string} value */
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    if (name.startsWith("data-")) {
      const key = name.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
      this.dataset[key] = String(value);
    }
  }

  /** @param {string} name */
  removeAttribute(name) {
    this.attributes.delete(name);
    if (name.startsWith("data-")) {
      const key = name.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
      delete this.dataset[key];
    }
  }

  /** @param {string} type @param {Function} listener */
  addEventListener(type, listener) {
    const list = this.listeners.get(type) ?? [];
    list.push(listener);
    this.listeners.set(type, list);
  }

  /** @param {string} type @param {any} event */
  dispatch(type, event = {}) {
    for (const listener of this.listeners.get(type) ?? []) listener({ target: this, ...event });
  }

  /** @param {FakeNode} node */
  replaceWith(node) {
    this.replacedWith = node;
  }

  /**
   * Only attribute selectors are needed: the shell looks up nav buttons and the
   * translation markers.
   *
   * @param {string} selector
   * @returns {FakeNode[]}
   */
  querySelectorAll(selector) {
    const match = /^\[data-([\w-]+)\]$/.exec(selector);
    if (!match) return [];
    const key = match[1].replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    const found = [];
    const walk = (node) => {
      for (const child of node.children) {
        if (child instanceof FakeNode && child.dataset[key] !== undefined) found.push(child);
        walk(child);
      }
    };
    walk(this);
    return found;
  }

  /** @returns {string} */
  text() {
    return this.textContent;
  }
}

export class FakeText {
  /** @param {string} value */
  constructor(value) {
    this.textContent = String(value);
    this.children = [];
    this.parentNode = null;
  }

  text() {
    return this.textContent;
  }
}

/**
 * Install the globals the shell expects.
 *
 * @returns {{ root: FakeNode, restore: () => void, globals: Record<string, any> }}
 */
export function installFakeDom({ languages = ["zh-CN"] } = {}) {
  const saved = {};
  for (const key of ["Node", "document", "window", "navigator", "location", "localStorage", "fetch", "setTimeout", "clearTimeout"]) {
    saved[key] = globalThis[key];
  }

  const root = new FakeNode("div");
  root.setAttribute("id", "app");

  const documentShim = {
    createElement: (tag) => new FakeNode(tag),
    createElementNS: (_namespace, tag) => new FakeNode(tag),
    createTextNode: (text) => new FakeText(text),
    getElementById: (id) => (id === "app" ? root : null),
    addEventListener() {},
    removeEventListener() {},
    visibilityState: "visible",
    title: "",
  };

  const storage = new Map();
  const windowShim = { addEventListener() {}, removeEventListener() {} };
  const locationShim = { protocol: "http:", hash: "" };
  const navigatorShim = { languages, language: languages[0] };
  const localStorageShim = {
    getItem: (key) => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, String(value)),
  };

  define("Node", FakeNode);
  define("document", documentShim);
  define("window", windowShim);
  define("navigator", navigatorShim);
  define("location", locationShim);
  define("localStorage", localStorageShim);

  // The polling loops would keep the process alive. Their first run still
  // happens (the promise is created by `start`), only the cadence is removed.
  define("setTimeout", () => 0);
  define("clearTimeout", () => {});

  return {
    root,
    globals: { document: documentShim, window: windowShim, location: locationShim },
    restore() {
      for (const [key, value] of Object.entries(saved)) {
        if (value === undefined) delete globalThis[key];
        else define(key, value);
      }
    },
  };
}

/** @param {string} key @param {any} value */
function define(key, value) {
  Object.defineProperty(globalThis, key, { value, writable: true, configurable: true });
}
