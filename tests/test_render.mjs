import assert from 'node:assert/strict';
import test from 'node:test';
import {replaceHTML} from '../localci/static/render.mjs';

// Just enough DOM: "HTML" is a nested [tag, ...children] spec, and replacing content
// creates fresh elements scrolled to 0, as a browser does.
function element(tag, children = []) {
  const el = {tagName: tag, parentElement: null, children: [], scrollLeft: 0, scrollTop: 0};
  for (const child of children) { child.parentElement = el; el.children.push(child); }
  el.querySelectorAll = () => { const all = []; const walk = node => { for (const c of node.children) { all.push(c); walk(c); } }; walk(el); return all; };
  Object.defineProperty(el, 'innerHTML', {set(spec) { el.children = []; for (const child of JSON.parse(spec).map(build)) { child.parentElement = el; el.children.push(child); } }});
  return el;
}
const build = ([tag, ...children]) => element(tag, children.map(build));
const table = rows => JSON.stringify([['DIV', ['TABLE', ...Array.from({length: rows}, () => ['TR'])]]]);

test('a wide table keeps its horizontal and vertical scroll position across a refresh', () => {
  const root = element('SECTION');
  root.innerHTML = table(3);
  Object.assign(root.children[0], {scrollLeft: 640, scrollTop: 25});
  replaceHTML(root, table(4));
  assert.equal(root.children[0].scrollLeft, 640);
  assert.equal(root.children[0].scrollTop, 25);
});

test('the container itself and nested scrolled elements keep their positions', () => {
  const root = element('DIV');
  root.innerHTML = JSON.stringify([['TABLE'], ['DETAILS', ['PRE']]]);
  root.scrollTop = 90;
  root.children[1].children[0].scrollLeft = 30;
  replaceHTML(root, JSON.stringify([['TABLE'], ['DETAILS', ['PRE']]]));
  assert.equal(root.scrollTop, 90);
  assert.equal(root.children[1].children[0].scrollLeft, 30);
});

test('content that changed shape is not given another element\'s position', () => {
  const root = element('SECTION');
  root.innerHTML = table(2);
  root.children[0].scrollLeft = 200;
  replaceHTML(root, JSON.stringify([['P']]));
  assert.equal(root.children[0].tagName, 'P');
  assert.equal(root.children[0].scrollLeft, 0);
  replaceHTML(root, JSON.stringify([]));
  assert.equal(root.children.length, 0);
});
