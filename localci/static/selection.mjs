const active = run => ['queued', 'running'].includes(run.state);
const key = run => `${run.repo}#${run.pr}`;
export function availableForRerun(runs, repos) {
  const enabled = new Set(repos.filter(repo => repo.enabled).map(repo => repo.name));
  const busy = new Set(runs.filter(active).map(key));
  return new Set(runs.filter(run => enabled.has(run.repo) && !active(run) && !busy.has(key(run)) && !run.retry_limit_reached).map(run => run.id));
}
export function selectedPRs(runs, selected) {
  const unique = new Map();
  for (const run of runs) if (selected.has(run.id) && !unique.has(key(run))) unique.set(key(run), run);
  return [...unique.values()];
}
export async function retrySelected(runs, selected, retry) {
  const results = [];
  for (const run of selectedPRs(runs, selected)) {
    try {
      const result = await retry(run.id);
      results.push({run, id: result.id, state: result.id ? 'queued' : 'active'});
    } catch (error) {
      results.push({run, state: 'error', message: error.message});
    }
  }
  return results;
}
