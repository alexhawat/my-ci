import {historyColumns, historyRows} from './history.mjs';
import {availableForRerun, selectedPRs, retrySelected} from './selection.mjs';
const $ = id => document.getElementById(id);
let state = {repos: [], runs: [], execution: {}}, selectedRepo = null, selectedRun = null;
let openPRs = [], prMode = 'open', prRequest = 0;
let historySort = 'created', historyDirection = 'desc';
const selectedRuns = new Set();
let retryingSelection = false;
let loading = false, currentView = 'overview', workflowChoices = [], editor = null, logEvents = [];
const esc = text => String(text ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const badge = s => `<span class="badge ${esc(s)}">${esc(s)}</span>`;
const date = t => t ? new Date(t*1000).toLocaleString(undefined, {dateStyle:'short',timeStyle:'medium'}) : '—';
const fixed = n => Number(n || 0).toLocaleString(undefined,{maximumFractionDigits:1});
const memory = n => n ? fixed(n / 2**30)+' GiB' : '—';
function elapsed(seconds) { if(seconds == null) return '—'; const s=Math.max(0,Math.floor(seconds)); return `${Math.floor(s/60)}m ${s%60}s`; }
function duration(r) {return r.started ? elapsed((r.finished||Date.now()/1000)-r.started) : '—';}
let workerError='';
function notice(message) {if($('settings').open) $('settings-error').textContent=message; $('notice').textContent=message; $('notice').hidden=!message;}
async function api(path, options={}) {
  const response=await fetch('/api'+path,{...options,headers:{'Content-Type':'application/json',...options.headers}});
  if(!response.ok) {const body=await response.json().catch(()=>({})); throw new Error(typeof body.detail==='string'?body.detail:JSON.stringify(body.detail||`Request failed (${response.status})`));}
  return response.headers.get('content-type')?.includes('json')?response.json():response.text();
}
async function view(name) {
  currentView=name; document.querySelectorAll('.view').forEach(el=>el.hidden=el.id!==name);
  document.querySelectorAll('.nav').forEach(el=>el.classList.toggle('active',el.dataset.view===name));
  $('heading').textContent={overview:'Overview',repositories:'Repositories',prs:'PRs',runs:'Run history',analytics:'Usage & analytics',execution:'Execution settings'}[name];
  if(name==='prs') await loadPRs(); if(name==='execution') await loadExecution(); if(name==='analytics') await loadAnalytics();
}
function runTable(runs, selectable=false, sortable=false) {
  if(!runs.length) return '<div class="empty"><strong>No matching runs.</strong>Enable a repository to check its open pull requests.</div>';
  return `<div class="table-wrap"><table class="history-table ${selectable?'selectable-table':''}"><thead><tr>${selectable?'<th class="select-column"><input id="select-visible-runs" type="checkbox" aria-label="Select all visible runs"></th>':''}${historyColumns.map(([key,label])=>sortable?`<th scope="col" aria-sort="${historySort===key?(historyDirection==='asc'?'ascending':'descending'):'none'}"><button class="sort-column" data-sort="${key}" aria-label="Sort by ${label}">${label} ${historySort===key?(historyDirection==='asc'?'↑':'↓'):'↕'}</button></th>`:`<th scope="col">${label}</th>`).join('')}<th scope="col">Actions</th></tr></thead><tbody>${runs.map(r=>`<tr>${selectable?`<td class="select-column"><input type="checkbox" data-select-run="${esc(r.id)}" aria-label="Select ${esc(r.repo)} #${r.pr} attempt ${r.attempt||1}" ${selectedRuns.has(r.id)?'checked':''} ${retryingSelection?'disabled':''} title="Select this run"></td>`:''}<td><strong>${esc(r.repo)} #${r.pr}</strong><small>${esc(r.title)}</small><small>${esc(r.id.slice(0,8))}</small></td><td>${badge(r.state)}${r.publish_error?'<small>Reporting needs attention</small>':''}</td><td>${esc(r.checks_summary||'Waiting for checks')}</td><td>${esc(r.branch||'—')}<small>${esc(r.actor)}</small></td><td>${esc(r.event)}<small>Attempt ${r.attempt||1}</small></td><td>${(r.workflow_sources||[]).map(w=>`<small>${esc(w.path.split('/').pop())} · ${w.version?'local v'+w.version:'GitHub base'}</small>`).join('')||'Review only'}</td><td>${date(r.created)}</td><td>${date(r.started)}</td><td>${date(r.finished)}</td><td>${elapsed((r.started||r.finished||Date.now()/1000)-r.created)}</td><td>${duration(r)}</td><td>${r.usage?.samples?fixed(r.usage.cpu_seconds/60):'—'}</td><td>${memory(r.usage?.peak_memory_bytes)}</td><td><code>${esc(r.head.slice(0,8))}</code></td><td><button class="button" data-run="${r.id}">View run ↗</button></td></tr>`).join('')}</tbody></table></div>`;
}
async function loadPRs() {
  const mode=prMode, request=++prRequest;
  try {
    const data=await api(`/prs?state=${mode}`);
    if(request!==prRequest || mode!==prMode)return;
    openPRs=data.prs;
    if(mode==='open')$('pr-count').textContent=openPRs.length;
    $('pr-summary').textContent=`${openPRs.length} ${mode==='closed'?'closed / merged':'open'} · ${data.last_poll?'synced '+date(data.last_poll):'waiting for first sync'}`;
    $('pr-errors').textContent=(data.errors||[]).map(r=>`${r.name}: sync failed; the list may be incomplete. ${r.error}`).join(' · ');
    filterPRs();
  } catch(e) {if(request===prRequest){$('pr-errors').textContent=e.message;$('pr-summary').textContent='Unable to load PRs';}}
}
function filterPRs() {
  const q=$('pr-search').value.toLowerCase();
  const prs=openPRs.filter(p=>[p.repo,`#${p.number}`,p.title,p.author,p.branch,p.state==='closed'?(p.merged?'merged':'closed'):(p.draft?'draft':'open'),p.latest_run?.state].join(' ').toLowerCase().includes(q));
  const iso=t=>t?date(Date.parse(t)/1000):'—';
  $('pr-list').innerHTML=prs.length?`<div class="table-wrap"><table class="pr-table"><thead><tr><th>Repository / PR</th><th>Title</th><th>Author / state</th><th>Branch → base</th><th>Local CI</th><th>Checks</th><th>Updated</th><th>Opened</th><th></th></tr></thead><tbody>${prs.map(p=>{
    const r=p.latest_run,current=r?.current,status=r?(current?badge(r.state):badge('outdated')):'<span class="muted">Not run</span>';
    return `<tr><td><a class="text-button" href="${esc(p.url)}" target="_blank" rel="noopener noreferrer">${esc(p.repo)} #${p.number} ↗</a></td><td><strong>${esc(p.title)}</strong></td><td>${esc(p.author)}<small>${p.state==='closed'?(p.merged?'Merged':'Closed'):(p.draft?'Draft':'Open')}${p.fork?' · Fork':''}</small></td><td>${esc(p.branch)} → ${esc(p.base_branch)}<small><code>${esc(p.head.slice(0,8))}</code></small></td><td>${status}<small>${esc(p.ci_eligibility)}</small>${p.sync_error?'<small>Sync needs attention</small>':''}</td><td>${r?`${current?'':'Previous revision: '}${esc(r.checks_summary||r.state)}`:'—'}</td><td>${iso(p.updated)}</td><td>${iso(p.created)}</td><td>${r?`<button class="button" data-run="${esc(r.id)}">View run ↗</button>`:'—'}</td></tr>`;
  }).join('')}</tbody></table></div>`:`<div class="empty"><strong>No matching ${prMode} pull requests.</strong>Only enabled repositories appear here.</div>`;
}
function selectionRuns() {return [...new Map([...state.runs,...(state.latest_runs||[])].map(r=>[r.id,r])).values()].sort((a,b)=>b.created-a.created);}
function overviewRuns() {return ($('overview-latest').checked?(state.latest_runs||state.runs):state.runs).slice(0,Number($('overview-limit').value));}
function renderOverviewRuns() {
  const visible=new Set(overviewRuns().map(r=>r.id));
  if(!retryingSelection)for(const id of selectedRuns)if(!visible.has(id))selectedRuns.delete(id);
  $('recent-runs').innerHTML=runTable(overviewRuns(),true);updateRunSelection();
}
function updateRunSelection() {
  const count=selectedPRs(selectionRuns(),selectedRuns).length,button=$('run-selected');
  button.disabled=retryingSelection||!count;$('clear-selection').disabled=retryingSelection;$('overview-limit').disabled=retryingSelection;$('overview-latest').disabled=retryingSelection;
  button.textContent=retryingSelection?'Creating new runs…':`Run selected as new runs${count?' ('+count+')':''}`;
  const available=availableForRerun(selectionRuns(),state.repos),ready=selectedPRs(selectionRuns(),selectedRuns).filter(r=>available.has(r.id)).length;
  $('selection-count').textContent=`${selectedRuns.size} selected · ${count} unique PR${count===1?'':'s'} · ${ready} ready to rerun`;
  const visible=overviewRuns(),all=$('select-visible-runs');
  if(all){all.disabled=retryingSelection||!visible.length;all.checked=!!visible.length&&visible.every(r=>selectedRuns.has(r.id));all.indeterminate=visible.some(r=>selectedRuns.has(r.id))&&!all.checked;}
}
$('recent-runs').addEventListener('change',e=>{
  if(retryingSelection)return;
  if(e.target.id==='select-visible-runs'){
    for(const r of overviewRuns()){if(e.target.checked)selectedRuns.add(r.id);else selectedRuns.delete(r.id);}
    renderOverviewRuns();
  }else if(e.target.dataset.selectRun){const id=e.target.dataset.selectRun;if(e.target.checked)selectedRuns.add(id);else selectedRuns.delete(id);updateRunSelection();}
});
$('overview-limit').addEventListener('change',renderOverviewRuns);
$('overview-latest').addEventListener('change',renderOverviewRuns);
$('clear-selection').addEventListener('click',()=>{if(retryingSelection)return;selectedRuns.clear();renderOverviewRuns();});
$('run-selected').addEventListener('click',async()=>{
  if(retryingSelection||!selectedRuns.size)return;
  retryingSelection=true;const runs=selectionRuns(),selection=new Set(selectedRuns);renderOverviewRuns();
  try{
    const results=await retrySelected(runs,selection,id=>api(`/runs/${id}/retry`,{method:'POST'}));
    const queued=results.filter(r=>r.state==='queued'),active=results.filter(r=>r.state==='active'),errors=results.filter(r=>r.state==='error');
    for(const result of results)if(result.state!=='error')for(const r of runs)if(r.repo===result.run.repo&&r.pr===result.run.pr)selectedRuns.delete(r.id);
    $('selection-result').textContent=`Created ${queued.length} new run${queued.length===1?'':'s'}.${active.length?' '+active.length+' PRs already have an active run.':''}${errors.length?' '+errors.map(r=>`${r.run.repo} #${r.run.pr}: ${r.message}`).join(' · '):''}`;
  }finally{retryingSelection=false;await refresh();renderOverviewRuns();}
});
function repoCards(repos) {return repos.length?`<div class="repo-grid">${repos.map(r=>`<article class="repo-card"><div class="eyebrow">${r.private?'PRIVATE':'PUBLIC'}</div><h3>${esc(r.name)}</h3><p>${esc(r.description||'No description')}</p><div class="bottom">${badge(r.enabled?'enabled':'disabled')}<button class="button" data-repo="${esc(r.name)}">Configure</button></div>${r.error?`<p>${esc(r.error)}</p>`:''}</article>`).join('')}</div>`:'<div class="empty"><strong>No repositories here yet.</strong>Choose a repository to start.</div>';}
function filterRepos() {const q=$('search').value.toLowerCase(); $('repo-list').innerHTML=repoCards(state.repos.filter(r=>r.name.toLowerCase().includes(q)));}
function filterRuns() {
  const repo=$('run-repo'), selected=repo.value;
  const names=[...new Set(state.runs.map(r=>r.repo))].sort();
  if(repo.dataset.names!==JSON.stringify(names)){
    repo.innerHTML='<option value="">All repositories</option>'+names.map(name=>`<option value="${esc(name)}">${esc(name)}</option>`).join('');
    repo.value=names.includes(selected)?selected:'';repo.dataset.names=JSON.stringify(names);
  }
  const runs=historyRows(state.runs,{query:$('run-search').value,repo:repo.value,result:$('run-result').value,days:Number($('run-period').value),sort:historySort,direction:historyDirection},{date,elapsed,fixed,memory});
  $('history-count').textContent=`${runs.length} of ${state.runs.length} recent runs (latest 100)`;
  $('all-runs').innerHTML=runTable(runs,false,true);
}
function render() {
  const enabled=state.repos.filter(r=>r.enabled), done=state.runs.filter(r=>['success','failure','error','blocked'].includes(r.state));
  $('app-setup').textContent=state.github_app?'✓ GitHub App':'Connect GitHub App';
  $('host-label').textContent=state.host||'local worker'; document.title=`my-ci · ${state.host||'local worker'}`;
  $('repo-count').textContent=state.repos.length; $('enabled').textContent=enabled.length; $('discovered').textContent=`${state.repos.length} repositories available`;
  $('queue').textContent=`${state.runs.filter(r=>r.state==='running').length} / ${state.runs.filter(r=>r.state==='queued').length}`;
  $('parallel-summary').textContent=`${state.execution.max_parallel_runs} parallel run slots${state.execution.paused?' · queue paused':''}`;
  $('pass').textContent=done.length?Math.round(done.filter(r=>r.state==='success').length/done.length*100)+'%':'—';
  $('disk').textContent=Math.floor((state.disk_free||0)/2**30)+' GB';
  $('account').textContent=state.login?`● ${state.login} · GitHub connected`:'Waiting for GitHub login';
  $('updated').textContent=state.last_poll?'Synced '+date(state.last_poll):'Waiting for first sync';
  renderOverviewRuns(); filterRuns(); $('enabled-repos').innerHTML=repoCards(enabled); filterRepos();
  // The worker's own error is shown while it lasts and cleared when it ends, without
  // replacing a message from an action the operator has just taken in a dialog.
  if(state.error){if(state.error!==workerError){workerError=state.error;$('notice').textContent=workerError;$('notice').hidden=false;}}
  else if(workerError){if($('notice').textContent===workerError)$('notice').hidden=true;workerError='';}
  $('worker-notice').hidden=!state.worker || state.worker.online;
}
async function refresh() {if(loading)return;loading=true;try{state=await api('/state');render();if(selectedRun&&$('run-detail').open)await refreshRun();if(currentView==='analytics')await loadAnalytics();if(currentView==='prs'&&prMode==='open')await loadPRs();}catch(e){notice(e.message);}finally{loading=false;}}
function variableRows(values) {
  $('variable-rows').innerHTML=''; for(const [name,value] of Object.entries(values)) addVariable(name,value);
  $('repo-vars').value=JSON.stringify(values,null,2);
}
function addVariable(name='',value='') {
  const row=document.createElement('div');row.className='variable-row';
  row.innerHTML=`<input class="variable-name" list="variable-names" aria-label="Variable name" placeholder="RUN_CODEQL" value="${esc(name)}" pattern="[A-Z][A-Z0-9_]*"><input class="variable-value" aria-label="Variable value" placeholder="false" value="${esc(value)}"><button type="button" class="button" data-remove-variable="true" aria-label="Remove variable">×</button>`;
  $('variable-rows').append(row);
  row.addEventListener('input',()=>{try{$('repo-vars').value=JSON.stringify(variables(),null,2);}catch{}});
}
function variables() {
  const result={};for(const row of document.querySelectorAll('.variable-row')) {const name=row.querySelector('.variable-name').value.trim(),value=row.querySelector('.variable-value').value;if(!name&&!value)continue;if(!/^[A-Z][A-Z0-9_]*$/.test(name))throw new Error('Variable names use uppercase letters, numbers and underscores.');if(Object.hasOwn(result,name))throw new Error('Duplicate variable: '+name);result[name]=value;}return result;
}
async function configure(name) {
  selectedRepo=state.repos.find(r=>r.name===name);const r=selectedRepo;
  $('settings-error').textContent='';$('settings-title').textContent=name;$('repo-enabled').checked=!!r.enabled;$('repo-run-bot-prs').checked=!!r.config.run_bot_prs;$('repo-review').checked=!!r.config.review;$('repo-review-threshold').value=r.config.review_failure_threshold||'major';
  $('repo-github-auth').value=r.config.github_auth||'none';$('repo-parallel').value=r.config.job_parallelism||1;$('repo-timeout').value=(r.config.timeout||7200)/60;$('repo-review-timeout').value=(r.config.review_timeout||3000)/60;$('repo-review-token-ceiling').value=r.config.review_token_ceiling??'';
  variableRows(r.config.variables||{});$('workflow-options').textContent='Loading workflows…';workflowChoices=[];renderSecrets();credentialChoices();$('settings').showModal();
  await loadWorkflowChoices(r.config.workflows||[]);
}
async function loadWorkflowChoices(selected) {
  const name=selectedRepo.name;
  try {const choices=await api(`/repos/${name}/workflows`);if(selectedRepo.name!==name)return;workflowChoices=choices;
    $('workflow-options').innerHTML=choices.length?choices.map(w=>`<div class="workflow-row"><label class="workflow ${!w.pr||w.review?'workflow-disabled':''}"><input type="checkbox" name="workflow" value="${esc(w.path)}" ${!w.pr||w.review?'disabled':''} ${selected.includes(w.path)?'checked':''}><span>${esc(w.name)}<small>${esc(w.path)} · ${w.local_version?'LOCAL v'+w.local_version:'GITHUB BASE → LOCAL DOCKER'}${w.review?' · use review toggle':!w.pr?' · not a PR workflow':''}</small><small>${esc((w.jobs||[]).join(' · '))}</small></span></label><button type="button" class="button" data-edit-workflow="${esc(w.path)}">Edit local copy</button></div>`).join(''):'<p class="muted">No workflows found. mergeCraft can still review PRs.</p>';
    $('variable-names').innerHTML=[...new Set(choices.flatMap(w=>w.variables||[]))].map(v=>`<option value="${esc(v)}"></option>`).join('');credentialChoices();
  }catch(e){$('workflow-options').textContent=e.message;}
}
function selectedWorkflows(){return [...document.querySelectorAll('input[name=workflow]:checked:not(:disabled)')].map(x=>x.value);}
function renderSecrets() {$('secret-list').innerHTML=(selectedRepo.secrets||[]).map(k=>`<button type="button" class="secret-chip" data-delete-secret="${esc(k)}" title="Delete this saved credential">${esc(k)} ×</button>`).join('')||'<span class="muted">No local credentials configured</span>';}
const reviewKeys={LLM_PROVIDER_1:'Provider identifier from your trusted base mergeCraft configuration, not an API key. Save its credential separately.',LLM_PROVIDER_1_API_KEY:'API key for the provider selected by LLM_PROVIDER_1. For OpenCode Go, paste your OpenCode Go provider key.',OPENAI_API_KEY:'OpenAI API key. Use only if the trusted mergeCraft configuration selects this provider.',ANTHROPIC_API_KEY:'Anthropic API key. Use only if the trusted mergeCraft configuration selects this provider.',OPENCODE_GO_API_KEY:'Direct OpenCode Go key name. If your mergeCraft configuration uses indexed providers, use LLM_PROVIDER_1_API_KEY instead.'};
function credentialChoices() {
  const ci=$('secret-scope').value==='ci', old=$('secret-choice').value;
  const detected=[...new Set(workflowChoices.filter(w=>selectedWorkflows().includes(w.path)).flatMap(w=>w.secrets||[]))];
  const saved=(selectedRepo?.secrets||[]).filter(k=>k.startsWith(ci?'ci:':'review:')).map(k=>k.split(':')[1]);
  const keys=[...new Set([...(ci?detected:Object.keys(reviewKeys)),...saved])].filter(k=>!['GITHUB_TOKEN','GH_TOKEN'].includes(k));
  $('secret-choice').innerHTML=keys.map(k=>`<option value="${esc(k)}">${esc(k)}${ci&&detected.includes(k)?' · referenced by workflow':''}</option>`).join('')+'<option value="custom">Custom credential name…</option>';
  if(keys.includes(old))$('secret-choice').value=old;credentialHelp();
}
function credentialHelp() {
  const key=$('secret-choice').value,ci=$('secret-scope').value==='ci';
  $('custom-secret-label').hidden=key!=='custom';$('secret-name').required=key==='custom';
  $('credential-help').textContent=key==='custom'?'Enter the exact environment/secret name expected by your workflow or provider configuration.':ci?`${key} supplies secrets.${key} in selected CI workflows. This value is available to their jobs; it is not a GitHub login token.`:reviewKeys[key]||'Provider setting for mergeCraft review only.';
}
async function openEditor(path) {
  $('editor-result').textContent='';$('editor-title').textContent=path;$('workflow-yaml').value='Loading…';$('workflow-editor').showModal();
  const data=await api(`/repos/${selectedRepo.name}/workflow?path=${encodeURIComponent(path)}`);
  editor={...data,repo:selectedRepo.name,expected_version:data.version};renderEditor(data);
  $('editor-version').innerHTML=`<option value="current">${data.version?'Active local v'+data.version:'Imported GitHub version'}</option>`+data.versions.filter(v=>v.version!==data.version).map(v=>`<option value="${v.version}">Local v${v.version} · ${date(v.created)}</option>`).join('');
}
function renderEditor(data) {$('workflow-yaml').value=data.content;$('editor-source').textContent=`${data.version?'Local version '+data.version:'GitHub import'} · source commit/ref ${data.source_ref}. Saving creates a new local version for future runs.`;}
async function openRun(id) {selectedRun=id;$('log-feedback').textContent='';$('run-detail').showModal();await refreshRun();}
const meta=(name,value)=>`<div><dt>${esc(name)}</dt><dd>${value}</dd></div>`;
function ciJobs(report) {
  return (report.jobs||[]).map(j=>`<details><summary>${esc(j.name)} · ${esc(j.state)}</summary><p>Workflow-step exit statuses; optional subchecks may skip.</p><ul>${j.checks.map(c=>`<li>${esc(c.name)}: ${esc(c.state)} · ${esc(c.duration)}</li>`).join('')}</ul><pre>${esc(j.summaries.join('\n'))}</pre></details>`).join('');
}
function reviewProfile(p) {
  if(!p)return '';
  return `<details><summary>Agent timing profile${p.complete?'':' · incomplete'}</summary><p>Agent: ${esc(p.agent_seconds)}s · MCP tools: ${esc(p.mcp_busy_seconds)}s · outside MCP: ${esc(p.outside_mcp_seconds)}s</p><p>${esc(p.outside_mcp_explanation)}</p><table><thead><tr><th>Tool</th><th>Calls</th><th>Seconds</th><th>Errors</th></tr></thead><tbody>${Object.entries(p.mcp).map(([name,v])=>`<tr><td>${esc(name)}</td><td>${esc(v.calls)}</td><td>${esc(v.seconds)}</td><td>${esc(v.errors)}</td></tr>`).join('')}</tbody></table></details>`;
}
function reviewRecord(report) {
  const r=report.record||{}, fields=[['Failure threshold',report.failure_threshold],['CLI exit code',r.exit_code],['Findings source',report.findings_source],['Provider',r.provider],['Model',r.model],['Agent verdict (diagnostic)',r.verdict],['Blast radius',r.blast_radius],['Model attempts',r.attempts],['Tokens',r.tokens],['Cost',r.cost],['LLM timing',r.timing],['Container wall time',r.container_seconds?`${r.container_seconds}s`:null],['Tool calls',r.tool_calls],['Tool retries',r.tool_retries],['Review image',r.image]];
  return `<details><summary>Review run record and coverage</summary><dl>${fields.map(([name,value])=>meta(name,esc(value??'Not recorded'))).join('')}</dl><p>File reads do not prove complete hunk coverage.</p><h4>Changed files</h4><pre>${esc((r.files_changed||[]).join('\n')||'Not recorded')}</pre><h4>Files recorded as read</h4><pre>${esc((r.files_read||[]).join('\n')||'Not recorded')}</pre></details>`;
}
async function refreshRun() {
  const id=selectedRun;const [r,files,log,events,samples,reports]=await Promise.all([api(`/runs/${id}`),api(`/runs/${id}/artifacts`),api(`/runs/${id}/log`),api(`/runs/${id}/events`),api(`/runs/${id}/resources`),api(`/runs/${id}/reports`)]);
  if(selectedRun!==id)return;
  $('run-title').textContent=`${r.repo} · PR #${r.pr}`;
  $('run-summary').innerHTML=`${badge(r.state)} &nbsp; ${esc(r.title)}<br>${esc(r.message||`Executing on ${state.host||'configured worker'}`)}${r.publish_error?'<br>GitHub reporting: '+esc(r.publish_error):''}`;
  $('run-metadata').innerHTML=meta('Run / attempt',`${esc(r.id)} / ${r.attempt}`)+meta('Retry budget',`${r.retries_remaining} left · ${r.max_attempts} total attempts per PR revision`)+meta('Branch / actor',`${esc(r.branch||'—')} / ${esc(r.actor||'—')}`)+meta('Event / runner',`pull_request / ${state.host||'configured worker'} · Docker`)+meta('Created',date(r.created))+meta('Started',date(r.started))+meta('Finished',date(r.finished))+meta('Queue / elapsed',`${r.started?elapsed(r.started-r.created):'Waiting'} / ${duration(r)}`)+meta('CPU / peak memory',`${r.usage?.samples?fixed(r.usage.cpu_seconds/60)+' core-min':'Not measured'} / ${memory(r.usage?.peak_memory_bytes)}`)+meta('Parallel jobs / resource limit',`${r.job_parallelism} / ${r.execution.cpus_per_run||'—'} CPUs · ${r.execution.memory_gb_per_run||'—'} GiB`)+meta('Review time limit',`${r.review_timeout/60} minutes`)+meta('GitHub authentication',r.github_auth==='gh'?'Host gh login (CI only)':'No token in CI')+meta('Repository reporting method',esc(r.reporting))+meta('Head commit',esc(r.head))+meta('Base commit',esc(r.base))+meta('Workflow definitions',(r.workflow_sources||[]).map(w=>`${esc(w.path)}<br>${w.version?'Local v'+w.version:'GitHub base'} · ${esc(w.source_ref.slice(0,12))}`).join('<br>')||'Review only');
  $('run-steps').innerHTML=`<div class="table-wrap"><table><thead><tr><th>Check</th><th>Status</th><th>Started</th><th>Finished</th><th>Duration</th><th>Detail</th></tr></thead><tbody>${r.steps.map(s=>`<tr><td>${esc(s.name)}</td><td>${badge(s.state)}</td><td>${date(s.started)}</td><td>${date(s.finished)}</td><td>${s.started?elapsed((s.finished||Date.now()/1000)-s.started):'—'}</td><td>${esc(s.message)}</td></tr>`).join('')}</tbody></table></div>`;
  $('run-steps').innerHTML+=Object.entries(reports).map(([kind,report])=>`<section><h3>${kind==='ci'?'CI result':'mergeCraft review'} · ${esc(report.result_label||report.state)}</h3>${report.policy_adjustment?'<p>This legacy result was re-evaluated from retained evidence; CI was not rerun.</p>':''}${kind==='ci'?ciJobs(report):report.findings_source==='evidence'?'<p>Recovered entries from retained evidence; draft/final entries may overlap. Recovery does not establish review completion.</p>':report.findings_source==='unavailable'?'<p>Findings unavailable; missing evidence is not a clean review.</p>':report.findings_source==='primary'&&!report.findings.length?'<p>No change-scoped findings in the available primary report. This alone is not an approval.</p>':''}${report.findings.map(f=>`<article><h4>${esc(f.severity)} · ${esc(f.path)}:${esc(f.start_line)}</h4><p>${esc(f.message)}</p>${f.evidence.map(e=>`<p>${esc(e)}</p>`).join('')}${f.remediation?`<p><strong>Suggested fix:</strong> ${esc(f.remediation)}</p>`:''}</article>`).join('')}${kind==='review'?`${reviewRecord(report)}${reviewProfile(report.record?.profile)}<details><summary>Analyzer results</summary>${(report.analyzers||[]).map(a=>`<p>${esc(a.name)}: ${esc(a.status)}</p>`).join('')}</details><details><summary>Run health · ${(report.run_health||[]).length} advisories</summary>${(report.run_health||[]).map(f=>`<p><strong>${esc(f.severity)}</strong> · ${esc(f.path)}: ${esc(f.message)} ${esc(f.remediation)}</p>`).join('')}</details>${report.narrative?`<details open><summary>Agent review summary</summary><pre>${esc(report.narrative)}</pre></details>`:''}`:''}${report.diagnostics.length?`<details open><summary>Diagnostic details</summary><pre>${esc(report.diagnostics.join('\n'))}</pre></details>`:''}</section>`).join('');
  $('cancel').hidden=!['running','queued'].includes(r.state);$('retry').hidden=['running','queued'].includes(r.state);$('retry').disabled=!!r.retry_limit_reached;$('retry').textContent=r.retry_limit_reached?'Retry limit reached':`↻ Retry latest PR (${r.retries_remaining} left)`;
  $('run-artifacts').innerHTML=files.length?'<h3>Artifacts</h3>'+files.map(f=>`<p><a class="text-button" href="/api/runs/${r.id}/artifact?path=${encodeURIComponent(f.path)}">↓ ${esc(f.path)} (${Math.ceil(f.bytes/1024)} KB)</a></p>`).join(''):'';
  $('export-log').href=`/api/runs/${r.id}/download-log`;
  const pre=$('run-log'),bottom=pre.scrollTop+pre.clientHeight>=pre.scrollHeight-30;pre.textContent=log;if(bottom)pre.scrollTop=pre.scrollHeight;
  logEvents=events;renderEvents();resourceChart(samples);
}
function renderEvents() {
  const raw=$('log-view').value==='raw',q=$('log-filter').value.toLowerCase();$('run-log').hidden=!raw;$('run-events').hidden=raw;
  const rows=logEvents.filter(e=>[e.phase,e.job,e.level,e.message].join(' ').toLowerCase().includes(q));
  const el=$('run-events'),bottom=el.scrollTop+el.clientHeight>=el.scrollHeight-40;
  el.innerHTML=rows.length?`<table><thead><tr><th>Timestamp</th><th>Phase</th><th>Job</th><th>Level</th><th>Message</th></tr></thead><tbody>${rows.map(e=>`<tr><td>${date(e.timestamp)}</td><td>${esc(e.phase)}</td><td>${esc(e.job||'—')}</td><td>${badge(e.level)}</td><td>${esc(e.message)}</td></tr>`).join('')}</tbody></table>`:'<p class="muted">No structured lines yet. Historical runs are available in Raw output and Export.</p>';
  if(bottom)el.scrollTop=el.scrollHeight;
}
function resourceChart(samples) {
  if(!samples.length){$('run-resources').innerHTML='<p class="muted">Resource sampling begins when a worker container starts. Older runs have no resource measurements.</p>';return;}
  const max=Math.max(100,...samples.map(s=>s.cpu_percent)),start=samples[0].timestamp,end=samples.at(-1).timestamp;
  const points=samples.map(s=>`${20+(s.timestamp-start)/Math.max(1,end-start)*960},${105-s.cpu_percent/max*90}`).join(' ');
  $('run-resources').innerHTML=`<h3>CPU over time · ${samples.length} samples</h3><svg class="resource-chart" viewBox="0 0 1000 120" role="img" aria-label="Sampled CPU usage, peak ${fixed(max)} percent; 100 percent is one CPU core"><polyline points="${points}" fill="none" stroke="currentColor" stroke-width="2"/><line x1="20" x2="980" y1="105" y2="105" stroke="#344259"/></svg><p class="muted">${date(start)} → ${date(end)} · ${fixed(max)}% chart maximum (100% = 1 CPU core). Samples about every 5 seconds.</p>`;
}
async function loadExecution() {
  loadUpdate();
  const data=await api('/execution'),s=data.settings,c=data.capacity;
  $('max-runs').value=s.max_parallel_runs;$('max-retries').value=s.max_retries;$('run-cpus').value=s.cpus_per_run;$('run-memory').value=s.memory_gb_per_run;$('queue-paused').checked=s.paused;
  $('host-capacity').textContent=c.cpus?`${state.host||'Configured worker'}: ${c.cpus} logical CPUs · ${c.memory_gb} GiB RAM. The scheduler reserves up to 2 CPUs and 4 GiB for the host where capacity permits. CI and review share each run’s total limit. Parallel review reserves up to 2 CPUs / 4 GiB (at most one quarter of each limit); CI gets the rest.`:'Reading host capacity…';capacityPlan();
}
let updateTimer=null;
const shortSha = sha => sha ? sha.slice(0,7) : 'unknown';
async function loadUpdate() {
  clearTimeout(updateTimer); updateTimer=null;
  let data;
  try {data=await api('/update');}
  catch(error) {
    $('update-status').textContent=`Waiting for my-ci to respond: ${error.message}`; $('update-now').disabled=true;
    if(currentView==='execution') updateTimer=setTimeout(loadUpdate,5000);
    return;
  }
  const u=data.update||{}, latest=data.latest||{}, active=['requested','running'].includes(u.state);
  const current=data.current?`<code>${esc(shortSha(data.current))}</code>`:'an unrecorded build';
  const upstream=latest.sha?`<a href="${esc(latest.url)}" target="_blank" rel="noreferrer"><code>${esc(shortSha(latest.sha))}</code></a> ${esc(latest.message)} · ${date(latest.date)}`:esc(latest.error||'unknown');
  const upToDate=Boolean(data.current&&latest.sha&&data.current===latest.sha);
  $('update-versions').innerHTML=`Running ${current}. Latest on ${esc(latest.repo||'upstream')}@${esc(latest.branch||'main')}: ${upstream}.${upToDate?' This deployment is up to date.':''}`;
  const status={
    requested:`Update requested ${date(u.requested)}. New runs are paused until it finishes; waiting for ${data.active_runs} active run${data.active_runs===1?'':'s'} to finish.`,
    running:`Updating since ${date(u.started)}: pulling, rebuilding and restarting my-ci. The dashboard disconnects for about a minute.`,
    succeeded:`Last update finished ${date(u.finished)}${u.to?`: now at ${esc(shortSha(u.to))}`:''}.`,
    failed:`Last update failed ${date(u.finished)}: ${esc(u.error||'see the log')}. Runs have resumed.`,
    cancelled:`Update cancelled ${date(u.finished)}.`,
  }[u.state];
  $('update-status').innerHTML=[status,data.unavailable&&!active?esc(data.unavailable):''].filter(Boolean).join(' ');
  $('update-now').disabled=active||Boolean(data.unavailable)||upToDate;
  $('update-now').textContent=upToDate?'Up to date':'Update to latest';
  $('update-cancel').hidden=u.state!=='requested';
  $('update-log-box').hidden=!u.log; $('update-log').textContent=u.log||'';
  if(active&&currentView==='execution') updateTimer=setTimeout(loadUpdate,5000);
}
function capacityPlan() {$('capacity-plan').textContent=`At full concurrency: up to ${Number($('max-runs').value)*Number($('run-cpus').value)} CPU cores and ${Number($('max-runs').value)*Number($('run-memory').value)} GiB allocated across workers. These are limits, not measured usage.`;}
async function loadAnalytics() {
  const data=await api(`/analytics?days=${$('analytics-days').value}`),t=data.totals;
  $('analytics-metrics').innerHTML=[['Runs',t.runs,`${t.success} passed · ${t.failure} failed/blocked`],['Run minutes',fixed(t.minutes),'Elapsed time summed across runs'],['CPU core-minutes',fixed(t.cpu_minutes),`${t.measured_runs} runs measured`],['Peak memory',memory(t.peak_memory_bytes),'Largest sampled single-run usage']].map(([label,value,detail])=>`<article><span>${label}</span><strong>${value}</strong><small>${detail}</small></article>`).join('');
  $('analytics-note').textContent=data.measurement;
  const max=Math.max(1,...data.daily.map(d=>d.minutes));
  $('analytics-chart').innerHTML=data.daily.length?data.daily.map(d=>`<div class="chart-row"><span>${d.day}</span><meter min="0" max="${max}" value="${d.minutes}" aria-label="${d.day}: ${fixed(d.minutes)} run minutes"></meter><span>${fixed(d.minutes)} min</span></div>`).join(''):'<p class="muted">Usage appears as new runs execute. Historical compute usage cannot be reconstructed.</p>';
  $('analytics-repos').innerHTML=`<div class="table-wrap"><table><thead><tr><th>Repository</th><th>Runs</th><th>Passed</th><th>Failed / blocked</th><th>Run minutes</th><th>CPU core-minutes</th><th>Peak memory</th><th>Measured runs</th></tr></thead><tbody>${data.repositories.map(r=>`<tr><td>${esc(r.repo)}</td><td>${r.runs}</td><td>${r.success}</td><td>${r.failure}</td><td>${fixed(r.minutes)}</td><td>${fixed(r.cpu_minutes)}</td><td>${memory(r.peak_memory_bytes)}</td><td>${r.measured_runs}</td></tr>`).join('')}</tbody></table></div>`;
}
document.addEventListener('click',async e=>{const target=e.target.closest('button');if(!target)return;try{
  if(target.dataset.view)await view(target.dataset.view);
  if(target.dataset.close)$(target.dataset.close).close();
  if(target.dataset.repo)await configure(target.dataset.repo);
  if(target.dataset.run)await openRun(target.dataset.run);
  if(target.dataset.editWorkflow)await openEditor(target.dataset.editWorkflow);
  if(target.dataset.removeVariable)target.closest('.variable-row').remove();
  if(target.dataset.deleteSecret){const[scope,name]=target.dataset.deleteSecret.split(':');await api(`/repos/${selectedRepo.name}/secrets/${scope}/${name}`,{method:'DELETE'});selectedRepo.secrets=selectedRepo.secrets.filter(s=>s!==target.dataset.deleteSecret);renderSecrets();credentialChoices();}
}catch(e){notice(e.message);}});
function setMenu(open) {
  $('sidebar').hidden=!open;document.body.classList.toggle('menu-closed',!open);
  $('menu-toggle').setAttribute('aria-expanded',String(open));
  $('menu-toggle').setAttribute('aria-label',open?'Hide sidebar':'Show sidebar');
  $('menu-toggle').title=open?'Hide sidebar':'Show sidebar';
  try{localStorage.setItem('localci-menu',open?'open':'closed');}catch{}
}
let menuOpen=true;try{menuOpen=localStorage.getItem('localci-menu')!=='closed';}catch{}
setMenu(menuOpen);
$('menu-toggle').addEventListener('click',()=>setMenu($('sidebar').hidden));
for(const id of ['run-repo','run-result','run-period'])$(id).addEventListener('change',filterRuns);
$('history-reset').addEventListener('click',()=>{for(const id of ['run-search','run-repo','run-result'])$(id).value='';$('run-period').value='0';historySort='created';historyDirection='desc';filterRuns();});
$('all-runs').addEventListener('click',e=>{const button=e.target.closest('[data-sort]');if(!button)return;historyDirection=historySort===button.dataset.sort && historyDirection==='asc'?'desc':'asc';historySort=button.dataset.sort;filterRuns();});
for(const mode of ['open','closed'])$('prs-'+mode).addEventListener('click',async()=>{
  if(prMode===mode)return;prMode=mode;openPRs=[];
  for(const value of ['open','closed']){$('prs-'+value).setAttribute('aria-pressed',String(value===mode));$('prs-'+value).classList.toggle('primary',value===mode);}
  $('pr-title').textContent=mode==='open'?'Open pull requests':'Closed & merged pull requests';
  $('pr-summary').textContent='Loading…';$('pr-errors').textContent='';$('pr-list').innerHTML='';
  await loadPRs();
});
$('search').addEventListener('input',filterRepos);$('run-search').addEventListener('input',filterRuns);$('pr-search').addEventListener('input',filterPRs);
$('add-variable').addEventListener('click',()=>addVariable());
$('apply-vars').addEventListener('click',()=>{try{const v=JSON.parse($('repo-vars').value);if(!v||Array.isArray(v)||typeof v!=='object'||Object.values(v).some(x=>typeof x!=='string'))throw new Error('Use a JSON object with string values, for example {"RUN_CODEQL":"false"}.');variableRows(v);}catch(e){notice(e.message);}});
$('settings-form').addEventListener('submit',async e=>{e.preventDefault();try{const config={enabled:$('repo-enabled').checked,run_bot_prs:$('repo-run-bot-prs').checked,review:$('repo-review').checked,review_failure_threshold:$('repo-review-threshold').value,github_auth:$('repo-github-auth').value,workflows:selectedWorkflows(),variables:variables(),timeout:Number($('repo-timeout').value)*60,review_timeout:Number($('repo-review-timeout').value)*60,review_token_ceiling:$('repo-review-token-ceiling').value===''?null:Number($('repo-review-token-ceiling').value),job_parallelism:Number($('repo-parallel').value)};await api(`/repos/${selectedRepo.name}`,{method:'PUT',body:JSON.stringify(config)});$('settings').close();notice('Settings saved. Existing runs keep their snapshot; Retry uses your latest configuration.');await refresh();}catch(e){notice(e.message);}});
$('secret-scope').addEventListener('change',credentialChoices);$('secret-choice').addEventListener('change',credentialHelp);$('workflow-options').addEventListener('change',credentialChoices);
$('secret-form').addEventListener('submit',async e=>{e.preventDefault();try{const scope=$('secret-scope').value,name=$('secret-choice').value==='custom'?$('secret-name').value:$('secret-choice').value;await api(`/repos/${selectedRepo.name}/secrets`,{method:'PUT',body:JSON.stringify({scope,name,value:$('secret-value').value})});$('secret-value').value='';selectedRepo.secrets=[...new Set([...selectedRepo.secrets,`${scope}:${name}`])];renderSecrets();notice('Credential saved. Its value cannot be read back.');}catch(e){notice(e.message);}});
$('workflow-save').addEventListener('click',async()=>{try{const result=await api(`/repos/${editor.repo}/workflow`,{method:'PUT',body:JSON.stringify({path:editor.path,content:$('workflow-yaml').value,source_ref:editor.source_ref,expected_version:editor.expected_version})});editor.expected_version=result.version;editor.version=result.version;editor.content=$('workflow-yaml').value;renderEditor(editor);$('editor-version').options[0].textContent='Active local v'+result.version;$('editor-version').value='current';$('editor-result').textContent=`Saved local v${result.version}. GitHub is unchanged. New runs will use this version when the workflow is selected.`;await loadWorkflowChoices(selectedWorkflows());}catch(e){$('editor-result').textContent=e.message;}});
$('workflow-reset').addEventListener('click',async()=>{try{await api(`/repos/${editor.repo}/workflow?path=${encodeURIComponent(editor.path)}`,{method:'DELETE'});$('workflow-editor').close();await loadWorkflowChoices(selectedWorkflows());notice('Future runs use the GitHub base workflow again. Local revision history is retained.');}catch(e){$('editor-result').textContent=e.message;}});
$('editor-version').addEventListener('change',async()=>{try{const v=$('editor-version').value;if(v==='current'){renderEditor(editor);return;}const data=await api(`/repos/${editor.repo}/workflow?path=${encodeURIComponent(editor.path)}&version=${v}`);renderEditor(data);}catch(e){$('editor-result').textContent=e.message;}});
$('workflow-yaml').addEventListener('keydown',e=>{if(e.key==='Tab'){e.preventDefault();const el=e.target,start=el.selectionStart,end=el.selectionEnd;el.setRangeText('  ',start,end,'end');}});
$('log-view').addEventListener('change',renderEvents);$('log-filter').addEventListener('input',renderEvents);
$('copy-log').addEventListener('click',async()=>{try{const log=await api(`/runs/${selectedRun}/download-log`);await navigator.clipboard.writeText(log);$('log-feedback').textContent='Full retained log copied.';}catch(e){$('log-feedback').textContent='Copy failed: '+e.message+'. Use Export to download the log.';}});
$('sync').addEventListener('click',async()=>{try{await api('/sync',{method:'POST'});notice('GitHub sync requested.');}catch(e){notice(e.message);}});
$('cancel').addEventListener('click',async()=>{try{await api(`/runs/${selectedRun}/cancel`,{method:'POST'});await refresh();}catch(e){notice(e.message);}});
$('retry').addEventListener('click',async()=>{try{await api(`/runs/${selectedRun}/retry`,{method:'POST'});$('run-detail').close();await refresh();}catch(e){notice(e.message);}});
$('execution-form').addEventListener('input',capacityPlan);
$('update-now').addEventListener('click',async()=>{
  if(!confirm('Update my-ci to the latest upstream commit? New runs pause, active runs finish first, then the dashboard and worker rebuild and restart.')) return;
  try {await api('/update',{method:'POST'}); notice('');} catch(error) {notice(error.message);}
  await loadUpdate();
});
$('update-cancel').addEventListener('click',async()=>{
  try {await api('/update',{method:'DELETE'}); notice('');} catch(error) {notice(error.message);}
  await loadUpdate();
});
$('execution-form').addEventListener('submit',async e=>{e.preventDefault();try{await api('/execution',{method:'PUT',body:JSON.stringify({max_parallel_runs:Number($('max-runs').value),max_retries:Number($('max-retries').value),cpus_per_run:Number($('run-cpus').value),memory_gb_per_run:Number($('run-memory').value),paused:$('queue-paused').checked})});$('execution-result').textContent='Saved. New containers start on demand within these limits.';await refresh();}catch(e){$('execution-result').textContent=e.message;}});
$('analytics-days').addEventListener('change',()=>loadAnalytics().catch(e=>notice(e.message)));
$('app-setup').addEventListener('click',()=>$('app-dialog').showModal());
$('app-form').addEventListener('submit',async e=>{e.preventDefault();try{const file=$('app-key').files[0];if(!file||file.size>20000)throw new Error('Choose a PEM key under 20 KB');const result=await api('/github-app',{method:'PUT',body:JSON.stringify({app_id:$('app-id').value,private_key:await file.text()})});$('app-key').value='';$('app-result').textContent='Connected '+result.name;await refresh();}catch(e){$('app-result').textContent=e.message;}});
await refresh();const run=new URLSearchParams(location.search).get('run');if(run)await openRun(run);setInterval(refresh,5000);
