export const historyColumns = [
  ['repository','Repository / PR'], ['result','Result'], ['checks','Checks'],
  ['branch','Branch / actor'], ['trigger','Trigger / attempt'], ['workflow','Workflow source'],
  ['created','Created'], ['started','Started'], ['finished','Finished'],
  ['queue','Queue wait'], ['duration','Duration'], ['cpu','CPU min'],
  ['memory','Peak memory'], ['commit','Commit'],
];
const compare = new Intl.Collator(undefined, {numeric:true, sensitivity:'base'});
export function historyValues(run, format, now=Date.now()/1000) {
  const queue = (run.started || run.finished || now) - run.created;
  const duration = run.started ? (run.finished || now) - run.started : null;
  const cpu = run.usage?.samples ? run.usage.cpu_seconds / 60 : null;
  const memory = run.usage?.peak_memory_bytes || null;
  const workflow = (run.workflow_sources || []).map(w => `${w.path} · ${w.version ? 'local v'+w.version : 'GitHub base'}`).join(' ') || 'Review only';
  const text = {
    repository:`${run.repo} #${run.pr} ${run.title || ''} ${run.id}`,
    result:`${run.state}${run.publish_error ? ' Reporting needs attention' : ''}`,
    checks:run.checks_summary || 'Waiting for checks', branch:`${run.branch || '—'} ${run.actor || ''}`,
    trigger:`${run.event || ''} Attempt ${run.attempt || 1}`, workflow,
    created:format.date(run.created), started:format.date(run.started), finished:format.date(run.finished),
    queue:format.elapsed(queue), duration:format.elapsed(duration),
    cpu:cpu == null ? '—' : format.fixed(cpu), memory:format.memory(memory), commit:run.head || '',
  };
  return {text, sort:{...text, repository:`${run.repo} #${run.pr}`, trigger:run.attempt || 1,
    created:run.created || null, started:run.started || null, finished:run.finished || null,
    queue, duration, cpu, memory}};
}
export function historyRows(runs, {query='',repo='',result='',days=0,sort='created',direction='desc'}={}, format, now=Date.now()/1000) {
  const q=query.trim().toLocaleLowerCase();
  const rows=runs.filter(r=>(!repo || r.repo===repo) && (!result || r.state===result) && (!days || r.created >= now-Number(days)*86400))
    .map(run=>({run,values:historyValues(run,format,now)}))
    .filter(({values})=>!q || Object.values(values.text).join(' ').toLocaleLowerCase().includes(q));
  rows.sort((a,b)=>{
    const x=a.values.sort[sort], y=b.values.sort[sort];
    if(x==null || y==null)return x==null ? (y==null ? 0 : 1) : -1;
    const order=typeof x==='number' && typeof y==='number' ? x-y : compare.compare(String(x),String(y));
    return direction==='desc' ? -order : order;
  });
  return rows.map(row=>row.run);
}
