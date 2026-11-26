// The dashboard refreshes every few seconds by replacing whole tables. A replaced
// element starts at scroll position 0, so a reader who had scrolled a wide table to
// the right was sent back to the left on every refresh. replaceHTML carries each
// scrolled element's offsets over to the element in the same place in the new content.

function pathTo(root, node) {
  const steps = [];
  for (let el = node; el !== root; el = el.parentElement) steps.unshift(Array.prototype.indexOf.call(el.parentElement.children, el));
  return steps;
}

function follow(root, steps) {
  let el = root;
  for (const step of steps) { el = el?.children[step]; if (!el) return null; }
  return el;
}

export function scrollPositions(root) {
  const found = [];
  for (const el of [root, ...root.querySelectorAll('*')])
    if (el.scrollLeft || el.scrollTop) found.push({path: pathTo(root, el), tag: el.tagName, left: el.scrollLeft, top: el.scrollTop});
  return found;
}

export function restoreScroll(root, positions) {
  for (const {path, tag, left, top} of positions) {
    const el = follow(root, path);
    // A different element at that place (rows changed shape) keeps its own position.
    if (el && el.tagName === tag) { el.scrollLeft = left; el.scrollTop = top; }
  }
}

export function replaceHTML(root, html) {
  const positions = scrollPositions(root);
  root.innerHTML = html;
  restoreScroll(root, positions);
}
