function showView(id){
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  window.scrollTo(0,0);
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
  if(btn){ btn.classList.toggle('on', expertMode); }
  if(sw){ sw.setAttribute('aria-checked', expertMode ? 'true' : 'false'); }
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
  { id:'domain_master', icon:'🏆', title:'Maître du domaine', desc:"Terminer les 5 scénarios" },
];

function unlockAchievements({ scenarioId, elapsed, hintsUsed, manCount, pathTaken }){
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
});
