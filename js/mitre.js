// ═══════════════════════════════════════════════════════════
// Matrice MITRE ATT&CK — vue de synthèse.
// Ne redéfinit aucune donnée : lit sc.deepDive.mitre, déjà présent
// sur chaque scénario technique (utilisé jusqu'ici uniquement sur
// l'écran "Analyse défensive" d'un scénario à la fois).
// ═══════════════════════════════════════════════════════════

function showMitreMatrix(){
  renderMitreMatrix();
  showView('view-mitre');
}

function renderMitreMatrix(){
  const grid = document.getElementById('mitre-grid');
  const summary = document.getElementById('mitre-summary');
  if(!grid) return;

  const ids = Object.keys(SCENARIOS).filter(id => {
    const sc = SCENARIOS[id];
    return sc.deepDive && sc.deepDive.mitre && sc.deepDive.mitre.length && id !== 'blueteam';
  });

  const uniqueTechniques = new Set();
  ids.forEach(id => SCENARIOS[id].deepDive.mitre.forEach(m => uniqueTechniques.add(m.id)));

  if(summary){
    summary.textContent = `${ids.length} scénario${ids.length>1?'s':''} cartographié${ids.length>1?'s':''} sur ${uniqueTechniques.size} technique${uniqueTechniques.size>1?'s':''} MITRE ATT&CK distinctes. Un aperçu de la couverture réelle du lab — clique un tag pour ouvrir sa fiche officielle.`;
  }

  grid.innerHTML = ids.map(id => {
    const sc = SCENARIOS[id];
    const done = !!completedScenarios[id];
    const name = scenarioDisplayName(sc);
    const chips = sc.deepDive.mitre.map(m =>
      `<a class="mitre-chip" href="https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/" target="_blank" rel="noopener" title="${m.name}"><span class="mitre-id">${m.id}</span> ${m.name}</a>`
    ).join('');
    return `<li class="gloss-card mitre-card">
      <h4>${done ? '✓ ' : ''}${name}</h4>
      <div class="mitre-badges" style="justify-content:flex-start;margin:0;">${chips}</div>
    </li>`;
  }).join('');
}
