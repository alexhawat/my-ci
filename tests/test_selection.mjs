import assert from 'node:assert/strict';
import test from 'node:test';
import {availableForRerun, selectedPRs, retrySelected} from '../localci/static/selection.mjs';
const run = (id, pr, state='failure', repo='o/r') => ({id, pr, state, repo});
test('allows finished results but excludes disabled repositories and already active PRs', () => {
  const runs=[run('failed',1),run('passed',2,'success'),run('cancelled',3,'cancelled'),run('old',4),run('new',4,'running'),run('queued',5,'queued'),run('disabled',6,'failure','o/off')];
  assert.deepEqual([...availableForRerun(runs,[{name:'o/r',enabled:1},{name:'o/off',enabled:0}])],['failed','passed','cancelled']);
});
test('multiple selected attempts create only one new run per PR', () => {
  const runs=[run('newest',1),run('other',2),run('older',1)];
  assert.deepEqual(selectedPRs(runs,new Set(['older','newest','other'])).map(r=>r.id),['newest','other']);
});
test('partial failures and active-race responses are reported without aborting the remaining selections', async () => {
  const runs=[run('a',1),run('b',2),run('c',3)], calls=[];
  const result=await retrySelected(runs,new Set(['a','b','c']),async id=>{
    calls.push(id); if(id==='a')throw new Error('PR closed');return {id:id==='b'?null:'fresh-attempt'};
  });
  assert.deepEqual(calls,['a','b','c']);
  assert.deepEqual(result.map(r=>r.state),['error','active','queued']);
  assert.equal(result[0].message,'PR closed');assert.equal(result[2].id,'fresh-attempt');
});
test('bulk selection excludes exhausted revision budgets', () => {
  const runs=[{...run('exhausted',1),retry_limit_reached:true}, {...run('available',2),retry_limit_reached:false}];
  assert.deepEqual([...availableForRerun(runs,[{name:'o/r',enabled:1}])],['available']);
});
