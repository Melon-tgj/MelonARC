/**
 * Inline icon set.
 *
 * Icons are drawn from path data instead of shipping an icon font or an image
 * sprite: one less asset to version, and the colour comes from `currentColor`,
 * so a token decides it. These are generic glyphs, not a brand asset.
 */

const SVG_NS = "http://www.w3.org/2000/svg";

/** @type {Record<string, string[]>} */
const PATHS = {
  overview: ["M4 14a8 8 0 1 1 16 0", "M12 14l3.5-4.5"],
  policies: ["M4 8l8-4 8 4-8 4z", "M4 12l8 4 8-4", "M4 16l8 4 8-4"],
  rules: ["M5 6h14", "M5 12h10", "M5 18h6"],
  connections: ["M3 12h4l2-5 3 10 2-5h5"],
  logs: ["M7 4h10v16H7z", "M10 8h4", "M10 12h4", "M10 16h3"],
  subscriptions: ["M6 4h8l4 4v12H6z", "M14 4v4h4", "M9 12h6", "M12 15v4", "M9.5 16.5L12 19l2.5-2.5"],
  settings: ["M4 7h16", "M4 12h16", "M4 17h16", "M9 5v4", "M15 10v4", "M7 15v4"],
  power: ["M12 4v7", "M7 7a7 7 0 1 0 10 0"],
  warning: ["M12 4l9 16H3z", "M12 10v4", "M12 17h.01"],
  dot: ["M12 12h.01"],
};

/**
 * @param {keyof typeof PATHS | string} name
 * @param {{ className?: string }} [options]
 * @returns {SVGElement}
 */
export function icon(name, { className = "icon" } = {}) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", className);

  for (const d of PATHS[name] ?? PATHS.dot) {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}
