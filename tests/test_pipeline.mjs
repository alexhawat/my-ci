import assert from 'node:assert/strict';
import test from 'node:test';
import {placeSlot} from '../localci/static/pipeline.mjs';

test('promote a backup, move a model to a new reviewer, and compact its former chain', () => {
  const original = [['one','two','three'], ['four']];
  const promoted = placeSlot(original, {row:0,column:2}, 0, 0, 'three edited');
  assert.deepEqual(promoted, [['three edited','one','two'],['four']]);
  const moved = placeSlot(promoted, {row:0,column:2}, 2, 0, 'two');
  assert.deepEqual(moved, [['three edited','one'],['four'],['two']]);
  assert.deepEqual(placeSlot(moved, {row:1,column:0}, 0, 1, 'four'), [['three edited','four','one'],['two']]);
  assert.deepEqual(original, [['one','two','three'], ['four']]);
});
