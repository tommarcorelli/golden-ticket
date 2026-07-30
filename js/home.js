function updateHomeBadges(){
  const ids = Object.keys(SCENARIOS);
  ids.forEach(id => {
    const badge = document.getElementById('badge-' + id);
    if(badge){
      if(completedScenarios[id]){
        badge.style.display = 'inline-block';
        badge.textContent = bestTimes[id] ? `✓ Terminé · ${bestTimes[id]}s` : '✓ Terminé';
      } else {
        badge.style.display = 'none';
      }
    }
  });
  const done = ids.filter(id => completedScenarios[id]).length;
  const track = document.getElementById('progress-track');
  if(track){
    track.innerHTML = `<span class="pt-fill">${done}</span> / ${ids.length} scénario${ids.length>1?'s':''} complété${done>1?'s':''}`
      + (done > 0 ? ` <button class="progress-reset" onclick="resetProgress()">↺ réinitialiser</button>` : '');
  }
}

function goToLesson(scenarioId){
  lessonScenarioId = scenarioId;

  const seedPanel = document.getElementById('libre-seed-panel');
  if(scenarioId === 'libre'){
    const seed = DomainGen.regenerateLibre();
    updateLibreSeedDisplay(seed);
    if(seedPanel) seedPanel.style.display = '';
  } else if(seedPanel){
    seedPanel.style.display = 'none';
  }

  renderLessonView(scenarioId);
}

// Redessine la leçon sans retirer un nouveau domaine (utilisé après reroll/chargement de seed).
function renderLessonView(scenarioId){
  const sc = SCENARIOS[scenarioId];

  document.getElementById('lesson-tag').textContent = sc.lessonTag;
  document.getElementById('lesson-slides').innerHTML = sc.lessonSlides.map((s,i) =>
    `<div class="slide ${i===0?'active':''}">
      <div class="slide-icon">${s.icon}</div>
      <h2>${s.title}</h2>
      ${s.html}
    </div>`
  ).join('');
  document.getElementById('lesson-dots').innerHTML = sc.lessonSlides.map((_,i) =>
    `<span class="${i===0?'on':''}"></span>`
  ).join('');

  currentSlide = 0;
  showView('view-lesson');
  renderSlide();
}

function updateLibreSeedDisplay(seed){
  const el = document.getElementById('libre-seed-code');
  if(el) el.textContent = seed;
  const input = document.getElementById('libre-seed-input');
  if(input) input.value = '';
}

function rerollLibreDomain(){
  const seed = DomainGen.regenerateLibre();
  updateLibreSeedDisplay(seed);
  // Le nom du domaine/employés a changé : on redessine la diapo de mission (sans re-tirer).
  if(lessonScenarioId === 'libre') renderLessonView('libre');
}

function loadLibreSeed(){
  const input = document.getElementById('libre-seed-input');
  const val = input ? input.value.trim() : '';
  if(!val) return;
  const seed = DomainGen.regenerateLibre(val);
  updateLibreSeedDisplay(seed);
  if(lessonScenarioId === 'libre') renderLessonView('libre');
}

function renderSlide(){
  const els = document.querySelectorAll('#lesson-slides .slide');
  els.forEach((el,i) => el.classList.toggle('active', i === currentSlide));
  const dots = document.querySelectorAll('#lesson-dots span');
  dots.forEach((d,i) => d.classList.toggle('on', i === currentSlide));
  document.getElementById('slide-back').style.visibility = currentSlide === 0 ? 'hidden' : 'visible';
  const nextBtn = document.getElementById('slide-next');
  nextBtn.textContent = currentSlide === els.length - 1 ? '▶ Lancer la mission' : 'Suivant →';
}

function nextSlide(){
  const total = document.querySelectorAll('#lesson-slides .slide').length;
  if(currentSlide === total - 1){
    startScenario(lessonScenarioId);
    return;
  }
  currentSlide++;
  renderSlide();
}
function prevSlide(){
  if(currentSlide === 0) return;
  currentSlide--;
  renderSlide();
}

function startScenario(scenarioId){
  showView('view-game');
  bootTerminal(scenarioId);
}

function backHome(){
  if(typeof stopMissionTimer === 'function') stopMissionTimer();
  replayToken++; // annule un éventuel replay en cours (évite des commandes fantômes après le retour à l'accueil)
  playbackActive = false;
  showView('view-home');
  updateHomeBadges();
}

function scenarioDisplayName(sc){
  const parts = sc.tag.split('·');
  return parts[1] ? parts[1].trim() : sc.tag;
}

let lbMode = 'normal';
function setLeaderboardMode(mode){
  lbMode = mode;
  document.querySelectorAll('#lb-tabs .lb-tab').forEach(t => t.classList.remove('active'));
  const idx = mode === 'expert' ? 1 : (mode === 'budget' ? 2 : 0);
  document.querySelectorAll('#lb-tabs .lb-tab')[idx]?.classList.add('active');
  renderLeaderboardBody();
}

function renderLeaderboardBody(){
  const ids = Object.keys(SCENARIOS);
  const host = document.getElementById('leaderboard-body');
  const suffix = lbMode === 'expert' ? '__expert' : (lbMode === 'budget' ? '__budget' : '');
  const totalRuns = ids.reduce((n, id) => n + (runHistory[id+suffix] ? runHistory[id+suffix].length : 0), 0);

  if(totalRuns === 0){
    const emptyMessages = {
      expert: `Aucune run en Mode Expert pour l'instant. Active-le sur l'accueil, puis termine une mission pour apparaître ici.`,
      budget: `Aucune run en Mode Budget pour l'instant. Active-le sur l'accueil, puis termine une mission avec un nombre de commandes limité (Mode Blue Team non concerné) pour apparaître ici.`,
      normal: `Aucune mission terminée pour l'instant. Termine un scénario pour apparaître ici — tes 5 meilleurs temps par scénario sont conservés.`
    };
    host.innerHTML = `<p class="lb-empty">${emptyMessages[lbMode] || emptyMessages.normal}</p>`;
  } else {
    host.innerHTML = ids.map(id => {
      const sc = SCENARIOS[id];
      const runs = runHistory[id+suffix] || [];
      if(runs.length === 0) return '';
      const medals = ['🥇','🥈','🥉'];
      const rows = runs.map((r,i) => {
        const d = new Date(r.date);
        const dateStr = isNaN(d) ? '' : d.toLocaleDateString('fr-FR', { day:'2-digit', month:'2-digit', year:'2-digit' });
        const cmdsStr = (typeof r.cmds === 'number') ? ` · ${r.cmds} cmd` : '';
        return `<div class="lb-row">
          <span class="lb-rank">${medals[i] || (i+1) + '.'}</span>
          <span class="lb-time">${r.time}s${cmdsStr}</span>
          <span class="lb-date">${dateStr}</span>
        </div>`;
      }).join('');
      return `<div class="lb-scenario ${sc.epic?'lb-epic':''}">
        <h4>${sc.epic ? '👑' : '🎫'} ${scenarioDisplayName(sc)}</h4>
        <div class="lb-rows">${rows}</div>
      </div>`;
    }).join('');
  }
}

function showLeaderboard(){
  renderAchievementsGrid();
  lbMode = 'normal';
  document.querySelectorAll('#lb-tabs .lb-tab').forEach((t,i) => t.classList.toggle('active', i===0));
  renderLeaderboardBody();
  showView('view-leaderboard');
}
function downloadReplay(){
  if(playbackActive){
    alert("Tu regardes déjà un replay : reviens à l'accueil et termine une vraie mission pour en exporter un nouveau.");
    return;
  }
  const sc = currentScenario();
  const payload = {
    kind:'golden-ticket-replay', version:1, exportedAt:new Date().toISOString(),
    scenarioId: state.scenarioId,
    seed: sc.seed || null,
    blueteamCase: state.scenarioId === 'blueteam' ? sc.currentCaseId : null,
    expertMode: !!state.expertMode,
    budgetMode: !!state.budgetMode,
    commands: replayLog
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type:'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const dateStr = new Date().toISOString().slice(0,10);
  a.href = url;
  a.download = `golden-ticket-replay-${state.scenarioId}-${dateStr}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function startReplayFromFile(file){
  if(!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    try{
      const data = JSON.parse(reader.result);
      if(data.kind !== 'golden-ticket-replay' || !Array.isArray(data.commands)){
        throw new Error('format invalide');
      }
      if(!SCENARIOS[data.scenarioId]) throw new Error('scénario inconnu');
      if(data.scenarioId === 'libre' && data.seed){
        DomainGen.regenerateLibre(data.seed);
      }
      if(data.scenarioId === 'blueteam' && data.blueteamCase){
        SCENARIOS.blueteam.forcedCase = data.blueteamCase;
      }
      if(typeof expertMode !== 'undefined') expertMode = !!data.expertMode;
      if(typeof budgetMode !== 'undefined') budgetMode = !!data.budgetMode;
      showView('view-game');
      bootTerminal(data.scenarioId, { playback:true });
      runReplayPlayback(data.commands);
    } catch(e){
      alert("Ce fichier ne ressemble pas à un replay Golden Ticket valide.");
    }
  };
  reader.readAsText(file);
}
