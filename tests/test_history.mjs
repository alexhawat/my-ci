import assert from 'node:assert/strict';
import test from 'node:test';
import {historyColumns,historyRows,historyValues} from '../localci/static/history.mjs';
const format={date:n=>n?new Date(n*1000).toLocaleString('en-GB'):'—',elapsed:n=>n==null?'—':`${Math.floor(n/60)}m ${Math.floor(n%60)}s`,fixed:n=>n.toFixed(1),memory:n=>n?`${n/2**30} GiB`:'—'};
const run=(id,pr,extra={})=>({id,pr,repo:'owner/project',state:'success',title:'Browser check',branch:'fix/browser',actor:'contributor',event:'pull_request',attempt:2,head:'abc1234',created:100,started:110,finished:230,checks_summary:'ci.yml: success',workflow_sources:[{path:'.github/workflows/ci.yml',version:3}],usage:{samples:1,cpu_seconds:7440,peak_memory_bytes:2**30},...extra});
test('search matches PR numbers, titles and every displayed data column',()=>{
  const r=run('run-identifier',124);
  assert.equal(historyRows([r],{query:'124'},format).length,1);
  const values=historyValues(r,format,500).text;
  for(const [column] of historyColumns)assert.equal(historyRows([r],{query:values[column]},format,500).length,1,column);
  assert.equal(historyRows([r],{query:'  BROWSER CHECK  '},format).length,1);
  assert.equal(historyRows([r],{query:'run-identifier'},format).length,1);
});
test('numeric PRs, durations and usage sort numerically; missing values stay last',()=>{
  const runs=[run('a',124,{finished:710}),run('b',9,{finished:230}),run('c',20,{started:null,finished:null,usage:null})];
  assert.deepEqual(historyRows(runs,{sort:'repository',direction:'asc'},format).map(r=>r.pr),[9,20,124]);
  assert.deepEqual(historyRows(runs,{sort:'duration',direction:'asc'},format).map(r=>r.id),['b','a','c']);
  assert.deepEqual(historyRows(runs,{sort:'duration',direction:'desc'},format).map(r=>r.id),['a','b','c']);
  assert.deepEqual(historyRows(runs,{sort:'memory',direction:'desc'},format).map(r=>r.id),['a','b','c']);
});
test('repository, result, created date and text filters combine',()=>{
  const runs=[run('match',124,{created:99999}),run('old',124),run('failed',124,{created:99999,state:'failure'}),run('other',124,{created:99999,repo:'other/repo'})];
  assert.deepEqual(historyRows(runs,{query:'124',repo:'owner/project',result:'success',days:1},format,100000).map(r=>r.id),['match']);
});
