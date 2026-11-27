// Positions in a row are dense: moving its first model promotes the next backup.
export function placeSlot(chains, source, targetRow, position, slot) {
  const rows = chains.map(row => [...row]);
  if (source) rows[source.row].splice(source.column, 1);
  if (targetRow === rows.length) rows.push([]);
  rows[targetRow].splice(position, 0, slot);
  return rows.filter(row => row.length);
}

export function pipelineEditor({get, escape}) {
  let rows = [], updates = new Map(), saved = new Set(), source = null;
  const dialog = get('slot-editor');
  function render() {
    get('pipeline-graph').innerHTML = rows.map((row, i) => {
      const nodes = row.map((slot, j) => `<button type="button" class="button pipeline-node" data-column="${j}"><small>${j ? 'Backup '+j : 'Primary'}</small><strong>${escape(slot.label)}</strong><small>${escape(slot.model)}</small></button>`);
      return `<div class="pipeline-row" data-row="${i}"><div class="pipeline-heading"><strong>Reviewer ${i+1}</strong>
        <button type="button" class="button" data-move="-1" aria-label="Move reviewer ${i+1} earlier" ${i===0?'disabled':''}>↑</button>
        <button type="button" class="button" data-move="1" aria-label="Move reviewer ${i+1} later" ${i===rows.length-1?'disabled':''}>↓</button></div>
        <div class="pipeline-chain">${nodes.join('<span aria-hidden="true">→</span>')}
        ${row.length<3?'<button type="button" class="button" data-backup>Add backup</button>':''}</div></div>`;
    }).join('') || '<p class="muted">Using the reviewer pipeline from the trusted base configuration.</p>';
    get('add-reviewer').disabled = rows.length >= 16;
  }
  function positions(preferred) {
    const row = Number(get('slot-chain').value);
    const count = (rows[row]?.length || 0) - Number(source?.row === row);
    get('slot-position').innerHTML = Array.from({length:count+1}, (_, i) => `<option value="${i}">${i?'Backup '+i:'Primary'}</option>`).join('');
    get('slot-position').value = Math.min(preferred ?? count, count);
  }
  function open(row, column) {
    source = column === undefined ? null : {row, column};
    const slot = source && rows[row][column];
    get('slot-form').reset();
    const keys = new Set([...saved, ...updates.keys(), ...rows.flat().map(s => s.credential)]);
    get('slot-key-names').innerHTML = [...keys].filter(k => /(^|_)API_KEY$/.test(k)).map(k => `<option value="${escape(k)}"></option>`).join('');
    get('slot-title').textContent = source ? 'Edit model' : rows[row] ? 'Add backup' : 'Add reviewer';
    get('slot-label').value = slot?.label || '';
    get('slot-model').value = slot?.model || '';
    get('slot-key').value = slot?.credential || '';
    get('slot-chain').innerHTML = rows.map((chain, i) => `<option value="${i}" ${chain.length>=3 && source?.row!==i?'disabled':''}>Reviewer ${i+1} · ${escape(chain[0].label)}</option>`).join('') + (rows.length < 16 ? `<option value="${rows.length}">New reviewer</option>` : '');
    get('slot-chain').value = row;
    positions(column);
    get('remove-slot').hidden = !source;
    get('slot-error').textContent = '';
    dialog.showModal();
  }
  get('add-reviewer').onclick = () => open(rows.length);
  get('pipeline-graph').onclick = event => {
    const button = event.target.closest('button');
    if (!button) return;
    const row = Number(button.closest('[data-row]').dataset.row);
    if (button.hasAttribute('data-move')) {
      const to = row + Number(button.dataset.move);
      [rows[row], rows[to]] = [rows[to], rows[row]];
      render();
    } else open(row, button.hasAttribute('data-column') ? Number(button.dataset.column) : undefined);
  };
  get('slot-chain').onchange = () => positions();
  get('remove-slot').onclick = () => {
    rows[source.row].splice(source.column, 1);
    rows = rows.filter(row => row.length);
    render();
    dialog.close();
  };
  get('slot-form').onsubmit = event => {
    event.preventDefault();
    const slot = {label:get('slot-label').value.trim(), model:get('slot-model').value.trim(), credential:get('slot-key').value.trim()};
    const value = get('slot-value').value;
    if (!slot.label || !/^[a-z0-9][a-z0-9_-]*\/[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(slot.model)) {
      get('slot-error').textContent = 'Enter a label and a model in provider/model format.';
      return;
    }
    if (!value && !saved.has(slot.credential) && !updates.has(slot.credential)) {
      get('slot-error').textContent = 'Enter the private API key for this new credential.';
      return;
    }
    const next = placeSlot(rows, source, Number(get('slot-chain').value), Number(get('slot-position').value), slot);
    if (next.some(row => new Set(row.map(s => JSON.stringify([s.model, s.credential]))).size !== row.length)) {
      get('slot-error').textContent = 'Choose a different model or API key for each position in a reviewer chain.';
      return;
    }
    if (value) updates.set(slot.credential, value);
    rows = next;
    render();
    dialog.close();
  };
  dialog.addEventListener('close', () => {get('slot-value').value = '';});
  return {
    reset(chains = [], names = []) {
      rows = structuredClone(chains);
      updates.clear();
      saved = new Set(names);
      render();
    },
    setKeys(names) { saved = new Set(names); },
    payload() {
      const keys = new Set(rows.flat().map(s => s.credential));
      return {review_pipeline:rows, review_key_updates:Object.fromEntries([...updates].filter(([key]) => keys.has(key)))};
    },
  };
}
