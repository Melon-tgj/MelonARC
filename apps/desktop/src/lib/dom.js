/**
 * Minimal DOM helpers.
 *
 * There is no view framework on purpose: the shell is small, and a dependency
 * free tree keeps the build reproducible without a package registry. Panels
 * build nodes with `el` and never touch innerHTML with untrusted values.
 */

/**
 * Create an element.
 *
 * @param {string} tag
 * @param {Record<string, unknown>} [props] `class`, `text`, `dataset`, `on<Event>`
 *   handlers, or any plain attribute. `false`/`null`/`undefined` are skipped so
 *   `cond && value` works inline.
 * @param {Node | string | Array<Node | string | false | null | undefined>} [children]
 * @returns {HTMLElement}
 */
export function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);

  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") {
      node.className = String(value);
    } else if (key === "text") {
      node.textContent = String(value);
    } else if (key === "dataset") {
      Object.assign(node.dataset, value);
    } else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else {
      node.setAttribute(key, value === true ? "" : String(value));
    }
  }

  append(node, children);
  return node;
}

/**
 * Append one child or a (possibly nested) list of children.
 *
 * @param {Node} node
 * @param {unknown} children
 */
export function append(node, children) {
  if (children === null || children === undefined || children === false) return;
  if (Array.isArray(children)) {
    for (const child of children) append(node, child);
    return;
  }
  node.append(children instanceof Node ? children : document.createTextNode(String(children)));
}

/**
 * Remove every child of a node.
 *
 * @param {Node} node
 */
export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}
