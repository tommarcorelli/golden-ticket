function showView(id){
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const el = document.getElementById(id);
  el.classList.add('active');
  window.scrollTo(0,0);
  el.focus({ preventScroll: true });
  const titles = {
    'view-home': 'Golden Ticket — Domain Breach Lab',
    'view-lesson': '📘 Leçon — Golden Ticket',
    'view-game': '🎫 Mission en cours — Golden Ticket',
    'view-glossary': '📖 Glossaire — Golden Ticket',
    'view-explain': '🛡️ Analyse — Golden Ticket',
    'view-leaderboard': '🏆 Classement — Golden Ticket'
  };
  document.title = titles[id] || 'Golden Ticket';
}

let lessonScenarioId = 'kerberoast';
let currentSlide = 0;

// ---------- mode expert (préférence simple, séparée de la progression) ----------
const EXPERT_KEY = 'goldenticket_expert_mode';
let expertMode = false;
try{ expertMode = localStorage.getItem(EXPERT_KEY) === '1'; }catch(e){ expertMode = false; }

function toggleExpertMode(){
  expertMode = !expertMode;
  try{ localStorage.setItem(EXPERT_KEY, expertMode ? '1' : '0'); }catch(e){ /* tant pis */ }
  renderExpertToggle();
}

function renderExpertToggle(){
  const btn = document.getElementById('expert-toggle');
  const sw = document.getElementById('expert-switch');
  if(btn){ btn.classList.toggle('on', expertMode); btn.setAttribute('aria-checked', expertMode ? 'true' : 'false'); }
  if(sw){ sw.setAttribute('aria-checked', expertMode ? 'true' : 'false'); }
}

// ---------- mode clair (préférence simple, séparée de la progression) ----------
const THEME_KEY = 'goldenticket_light_mode';
let lightMode = false;
try{ lightMode = localStorage.getItem(THEME_KEY) === '1'; }catch(e){ lightMode = false; }

function applyTheme(){
  document.documentElement.classList.toggle('light-mode', lightMode);
  const btn = document.getElementById('theme-toggle');
  if(btn){
    btn.setAttribute('aria-pressed', lightMode ? 'true' : 'false');
    btn.childNodes[0].textContent = lightMode ? '☀️' : '🌙';
  }
}

function toggleLightMode(){
  lightMode = !lightMode;
  try{ localStorage.setItem(THEME_KEY, lightMode ? '1' : '0'); }catch(e){ /* tant pis */ }
  applyTheme();
}

// ---------- effets sonores (préférence simple, séparée de la progression) ----------
const SOUND_KEY = 'goldenticket_sound_fx';
let soundFxEnabled = true;
try{ const stored = localStorage.getItem(SOUND_KEY); soundFxEnabled = stored === null ? true : stored === '1'; }catch(e){ soundFxEnabled = true; }

function applySoundToggle(){
  const btn = document.getElementById('sound-toggle');
  if(btn){
    btn.setAttribute('aria-pressed', soundFxEnabled ? 'true' : 'false');
    btn.childNodes[0].textContent = soundFxEnabled ? '🔊' : '🔇';
  }
}

function toggleSoundFx(){
  soundFxEnabled = !soundFxEnabled;
  try{ localStorage.setItem(SOUND_KEY, soundFxEnabled ? '1' : '0'); }catch(e){ /* tant pis */ }
  applySoundToggle();
}

// ---------- konami code (easter egg global, marche sur tous les écrans) ----------
const KONAMI_SEQUENCE = ['arrowup','arrowup','arrowdown','arrowdown','arrowleft','arrowright','arrowleft','arrowright','b','a'];
let konamiProgress = 0;
document.addEventListener('keydown', (e) => {
  const key = e.key.toLowerCase();
  if(key === KONAMI_SEQUENCE[konamiProgress]){
    konamiProgress++;
    if(konamiProgress === KONAMI_SEQUENCE.length){
      konamiProgress = 0;
      triggerKonamiEasterEgg();
    }
  } else {
    konamiProgress = (key === KONAMI_SEQUENCE[0]) ? 1 : 0;
  }
});

function triggerKonamiEasterEgg(message, pieces){
  const host = document.createElement('div');
  host.className = 'konami-host';
  document.body.appendChild(host);
  const set = pieces || ['🎫','👑','✨','🔑','🏆'];
  for(let i=0;i<50;i++){
    const span = document.createElement('span');
    span.className = 'confetti-piece';
    span.textContent = set[i % set.length];
    span.style.left = (Math.random()*100) + '%';
    span.style.animationDelay = (Math.random()*0.8) + 's';
    span.style.animationDuration = (2.4 + Math.random()*1.6) + 's';
    span.style.fontSize = (14 + Math.random()*14) + 'px';
    host.appendChild(span);
  }
  const toast = document.createElement('div');
  toast.className = 'konami-toast';
  toast.textContent = message || "🎮 Code secret trouvé. Pas de vies infinies ici, juste du style.";
  document.body.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 400);
  }, 3200);
  setTimeout(() => host.remove(), 4200);
}

// ---------- code clavier caché "goldenticket" (tapé librement, hors saisie terminal) ----------
const WORD_CODE = 'goldenticket';
let wordBuffer = '';
document.addEventListener('keydown', (e) => {
  const active = document.activeElement;
  if(active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA')) return;
  if(e.key.length !== 1) return;
  wordBuffer = (wordBuffer + e.key.toLowerCase()).slice(-WORD_CODE.length);
  if(wordBuffer === WORD_CODE){
    wordBuffer = '';
    triggerKonamiEasterEgg("🎫 Tu as tapé le mot magique. Golden Ticket débloqué (façon de parler).", ['🎫','✨','💛']);
  }
});

// ---------- triple-clic caché sur le domaine ----------
function initDomainEasterEgg(){
  const pill = document.querySelector('.domain-pill');
  if(!pill) return;
  let clicks = 0;
  let resetTimer = null;
  pill.style.cursor = 'pointer';
  pill.addEventListener('click', () => {
    clicks++;
    clearTimeout(resetTimer);
    resetTimer = setTimeout(() => { clicks = 0; }, 900);
    if(clicks >= 3){
      clicks = 0;
      triggerKonamiEasterEgg("🏰 CORP.LOCAL vous salue. Le domaine n'a aucun secret pour vous.", ['🏰','🔑','🛡️']);
    }
  });
}

// ---------- progression persistante (localStorage) ----------
const PROGRESS_KEY = 'goldenticket_progress_v1';

function loadProgress(){
  try{
    const raw = localStorage.getItem(PROGRESS_KEY);
    if(!raw) return { completed:{}, bestTimes:{}, runHistory:{}, achievements:{}, librePaths:{} };
    const parsed = JSON.parse(raw);
    return {
      completed: parsed.completed || {},
      bestTimes: parsed.bestTimes || {},
      runHistory: parsed.runHistory || {},
      achievements: parsed.achievements || {},
      librePaths: parsed.librePaths || {}
    };
  }catch(e){
    return { completed:{}, bestTimes:{}, runHistory:{}, achievements:{}, librePaths:{} };
  }
}
function saveProgress(){
  try{
    localStorage.setItem(PROGRESS_KEY, JSON.stringify({
      completed: completedScenarios, bestTimes: bestTimes, runHistory: runHistory,
      achievements: achievements, librePaths: librePaths
    }));
  }catch(e){ /* stockage indisponible (navigation privée...), tant pis */ }
}

function pruneOrphanIds(obj){
  // évite qu'un id de scénario renommé/supprimé reste coincé en localStorage
  // (gère aussi les clés suffixées "id__expert" du mode expert)
  const validIds = Object.keys(SCENARIOS);
  Object.keys(obj).forEach(id => {
    const baseId = id.endsWith('__expert') ? id.slice(0, -'__expert'.length) : id;
    if(!validIds.includes(baseId)) delete obj[id];
  });
  return obj;
}

const RUN_HISTORY_MAX = 5;
const savedProgress = loadProgress();
const completedScenarios = pruneOrphanIds(savedProgress.completed);
const bestTimes = pruneOrphanIds(savedProgress.bestTimes);
const runHistory = pruneOrphanIds(savedProgress.runHistory);
const achievements = savedProgress.achievements;
const librePaths = savedProgress.librePaths;

function markScenarioComplete(scenarioId){
  completedScenarios[scenarioId] = true;
  saveProgress();
  updateHomeBadges();
}

function recordBestTime(scenarioId, elapsed, isExpert){
  const key = isExpert ? scenarioId + '__expert' : scenarioId;
  if(!bestTimes[key] || elapsed < bestTimes[key]){
    bestTimes[key] = elapsed;
  }
  if(!runHistory[key]) runHistory[key] = [];
  runHistory[key].push({ time: elapsed, date: new Date().toISOString() });
  runHistory[key].sort((a,b) => a.time - b.time);
  runHistory[key] = runHistory[key].slice(0, RUN_HISTORY_MAX);
  saveProgress();
  updateHomeBadges();
}

function resetProgress(){
  if(!confirm('Effacer ta progression sauvegardée (scénarios terminés, meilleurs temps, classement, succès) ? Cette action est irréversible.')) return;
  Object.keys(completedScenarios).forEach(k => delete completedScenarios[k]);
  Object.keys(bestTimes).forEach(k => delete bestTimes[k]);
  Object.keys(runHistory).forEach(k => delete runHistory[k]);
  Object.keys(achievements).forEach(k => delete achievements[k]);
  Object.keys(librePaths).forEach(k => delete librePaths[k]);
  saveProgress();
  updateHomeBadges();
}

// ---------- succès ----------
const ACHIEVEMENTS = [
  { id:'no_hint',       icon:'🎯', title:'Sans indice',    desc:"Terminer une mission sans cliquer sur Indice" },
  { id:'speedster',     icon:'⚡', title:'Éclair',          desc:"Terminer une mission en moins de 45s" },
  { id:'curious',       icon:'🧠', title:'Curieux',         desc:"Consulter man au moins 3 fois dans une mission" },
  { id:'both_paths',    icon:'🧭', title:'Les deux routes', desc:"Terminer le mode libre par ses deux chemins" },
  { id:'golden_finisher',icon:'👑', title:'Golden Ticket',  desc:"Terminer le Chapitre Final" },
  { id:'domain_master', icon:'🏆', title:'Maître du domaine', desc:"Terminer tous les scénarios" },
  { id:'ghost',         icon:'🥷', title:'Fantôme',          desc:"Terminer une mission sans jamais déclencher l'alerte SOC" },
];

function unlockAchievements({ scenarioId, elapsed, hintsUsed, manCount, pathTaken, opsecEnabled, detected }){
  const newlyUnlocked = [];
  const unlock = (id) => {
    if(!achievements[id]){
      achievements[id] = { date: new Date().toISOString() };
      const def = ACHIEVEMENTS.find(a => a.id === id);
      if(def) newlyUnlocked.push(def);
    }
  };

  if(hintsUsed === 0) unlock('no_hint');
  if(elapsed < 45) unlock('speedster');
  if(manCount >= 3) unlock('curious');
  if(scenarioId === 'goldenticket') unlock('golden_finisher');
  if(opsecEnabled && !detected) unlock('ghost');

  if(scenarioId === 'libre' && pathTaken){
    librePaths[pathTaken] = true;
    if(librePaths.acl && librePaths.pth) unlock('both_paths');
  }

  const allIds = Object.keys(SCENARIOS);
  if(allIds.every(id => completedScenarios[id])) unlock('domain_master');

  saveProgress();
  return newlyUnlocked;
}

function renderAchievementsGrid(){
  const host = document.getElementById('achievements-grid');
  if(!host) return;
  host.innerHTML = ACHIEVEMENTS.map(a => {
    const unlocked = !!achievements[a.id];
    return `<div class="ach-badge ${unlocked?'unlocked':''}">
      <span class="ach-icon">${a.icon}</span>
      <span class="ach-title">${a.title}</span>
      <span class="ach-desc">${unlocked ? a.desc : '???'}</span>
    </div>`;
  }).join('');
}

// ---------- export / import ----------
function exportProgress(){
  const payload = {
    version:1, exportedAt:new Date().toISOString(),
    completed: completedScenarios, bestTimes: bestTimes, runHistory: runHistory,
    achievements: achievements, librePaths: librePaths
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type:'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const dateStr = new Date().toISOString().slice(0,10);
  a.href = url;
  a.download = `golden-ticket-progression-${dateStr}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function importProgress(file){
  if(!file) return;
  if(!confirm('Importer ce fichier remplacera ta progression actuelle sur cet appareil. Continuer ?')) return;
  const reader = new FileReader();
  reader.onload = () => {
    try{
      const data = JSON.parse(reader.result);
      if(typeof data !== 'object' || data === null) throw new Error('format invalide');
      Object.keys(completedScenarios).forEach(k => delete completedScenarios[k]);
      Object.keys(bestTimes).forEach(k => delete bestTimes[k]);
      Object.keys(runHistory).forEach(k => delete runHistory[k]);
      Object.keys(achievements).forEach(k => delete achievements[k]);
      Object.keys(librePaths).forEach(k => delete librePaths[k]);
      Object.assign(completedScenarios, pruneOrphanIds(data.completed || {}));
      Object.assign(bestTimes, pruneOrphanIds(data.bestTimes || {}));
      Object.assign(runHistory, pruneOrphanIds(data.runHistory || {}));
      Object.assign(achievements, data.achievements || {});
      Object.assign(librePaths, data.librePaths || {});
      saveProgress();
      updateHomeBadges();
      renderAchievementsGrid();
      alert('Progression importée avec succès.');
    }catch(e){
      alert("Fichier invalide : impossible d'importer cette progression.");
    }
    document.getElementById('import-file-input').value = '';
  };
  reader.readAsText(file);
}

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
  const idx = mode === 'expert' ? 1 : 0;
  document.querySelectorAll('#lb-tabs .lb-tab')[idx]?.classList.add('active');
  renderLeaderboardBody();
}

function renderLeaderboardBody(){
  const ids = Object.keys(SCENARIOS);
  const host = document.getElementById('leaderboard-body');
  const suffix = lbMode === 'expert' ? '__expert' : '';
  const totalRuns = ids.reduce((n, id) => n + (runHistory[id+suffix] ? runHistory[id+suffix].length : 0), 0);

  if(totalRuns === 0){
    host.innerHTML = lbMode === 'expert'
      ? `<p class="lb-empty">Aucune run en Mode Expert pour l'instant. Active-le sur l'accueil, puis termine une mission pour apparaître ici.</p>`
      : `<p class="lb-empty">Aucune mission terminée pour l'instant. Termine un scénario pour apparaître ici — tes 5 meilleurs temps par scénario sont conservés.</p>`;
  } else {
    host.innerHTML = ids.map(id => {
      const sc = SCENARIOS[id];
      const runs = runHistory[id+suffix] || [];
      if(runs.length === 0) return '';
      const medals = ['🥇','🥈','🥉'];
      const rows = runs.map((r,i) => {
        const d = new Date(r.date);
        const dateStr = isNaN(d) ? '' : d.toLocaleDateString('fr-FR', { day:'2-digit', month:'2-digit', year:'2-digit' });
        return `<div class="lb-row">
          <span class="lb-rank">${medals[i] || (i+1) + '.'}</span>
          <span class="lb-time">${r.time}s</span>
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
      showView('view-game');
      bootTerminal(data.scenarioId, { playback:true });
      runReplayPlayback(data.commands);
    } catch(e){
      alert("Ce fichier ne ressemble pas à un replay Golden Ticket valide.");
    }
  };
  reader.readAsText(file);
}

function downloadCertificate(){
  const sc = SCENARIOS[state.scenarioId];
  const name = (prompt('Ton nom ou pseudo pour le certificat :', 'CORP\\Domain Admin') || 'CORP\\Domain Admin').slice(0, 40);
  const timeText = document.getElementById('mc-time').textContent;
  const cmdsText = document.getElementById('mc-cmds').textContent;
  const hintsText = document.getElementById('mc-hints').textContent;
  const modeText = state.expertMode ? '🎓 Mode Expert' : 'Mode Normal';
  const dateStr = new Date().toLocaleDateString('fr-FR', { day:'2-digit', month:'long', year:'numeric' });

  const canvas = document.createElement('canvas');
  canvas.width = 1200; canvas.height = 800;
  const ctx = canvas.getContext('2d');

  const bg = ctx.createLinearGradient(0, 0, 1200, 800);
  bg.addColorStop(0, '#0d0b17'); bg.addColorStop(1, '#1a1030');
  ctx.fillStyle = bg; ctx.fillRect(0, 0, 1200, 800);

  ctx.strokeStyle = '#f2b705'; ctx.lineWidth = 4;
  ctx.strokeRect(30, 30, 1140, 740);
  ctx.strokeStyle = 'rgba(242,183,5,0.35)'; ctx.lineWidth = 1;
  ctx.strokeRect(48, 48, 1104, 704);

  ctx.textAlign = 'center';
  ctx.fillStyle = '#f2b705';
  ctx.font = '700 24px monospace';
  ctx.fillText('🎫 DOMAIN BREACH LAB', 600, 128);

  ctx.fillStyle = '#ffffff';
  ctx.font = '700 50px Georgia, "Times New Roman", serif';
  ctx.fillText('Certificat de Golden Ticket', 600, 205);

  ctx.fillStyle = '#b8b3c9';
  ctx.font = '20px monospace';
  ctx.fillText('décerné à', 600, 262);

  ctx.fillStyle = '#f2b705';
  ctx.font = '700 38px monospace';
  ctx.fillText(name, 600, 320);

  ctx.fillStyle = '#e5e1f0';
  ctx.font = '18px monospace';
  ctx.fillText("pour avoir compromis intégralement le domaine CORP.LOCAL", 600, 375);
  ctx.fillText("Kerberoasting → Pass-the-Hash → Abus d'ACL → Golden Ticket (DCSync + forge krbtgt)", 600, 402);

  ctx.fillStyle = '#a78bfa';
  ctx.font = '700 22px monospace';
  ctx.fillText(`⏱ ${timeText}    💻 ${cmdsText} commandes    💡 ${hintsText} indices    ${modeText}`, 600, 470);

  ctx.fillStyle = '#7a7690';
  ctx.font = '16px monospace';
  ctx.fillText(dateStr, 600, 525);

  ctx.strokeStyle = 'rgba(242,183,5,0.3)'; ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(400, 560); ctx.lineTo(800, 560); ctx.stroke();

  ctx.fillStyle = '#4a4560';
  ctx.font = '13px monospace';
  ctx.fillText('Simulation pédagogique — Golden Ticket Lab. Aucun système réel compromis.', 600, 700);

  const url = canvas.toDataURL('image/png');
  const a = document.createElement('a');
  a.href = url;
  a.download = 'golden-ticket-certificat.png';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function showExplain(){
  const sc = SCENARIOS[state.scenarioId];
  document.getElementById('explain-tag').textContent = `🛡️ ANALYSE · ${sc.tag.split('·')[1] ? sc.tag.split('·')[1].trim() : sc.tag}`;
  document.getElementById('explain-title').textContent = 'Pourquoi ça marche';
  document.getElementById('explain-why').textContent = sc.deepDive.why;
  document.getElementById('explain-defenses').innerHTML = sc.deepDive.defenses.map(d => `<li>${d}</li>`).join('');
  showView('view-explain');
}

document.addEventListener('DOMContentLoaded', () => {
  initTerminalInput();
  updateHomeBadges();
  renderExpertToggle();
  applyTheme();
  applySoundToggle();
  initLogoEasterEgg();
  initDomainEasterEgg();
});

function initLogoEasterEgg(){
  const brand = document.querySelector('.brand');
  if(!brand) return;
  let clicks = 0;
  let resetTimer = null;
  brand.style.cursor = 'pointer';
  brand.addEventListener('click', () => {
    clicks++;
    clearTimeout(resetTimer);
    resetTimer = setTimeout(() => { clicks = 0; }, 1200);
    if(clicks >= 7){
      clicks = 0;
      triggerKonamiEasterEgg();
    }
  });
}

if('serviceWorker' in navigator){
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js').catch(() => { /* pas grave, le jeu marche sans */ });
  });
}
