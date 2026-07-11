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

// ---------- progression persistante (localStorage) ----------
const PROGRESS_KEY = 'goldenticket_progress_v1';

function loadProgress(){
  try{
    const raw = localStorage.getItem(PROGRESS_KEY);
    if(!raw) return { completed:{}, bestTimes:{}, runHistory:{} };
    const parsed = JSON.parse(raw);
    return { completed: parsed.completed || {}, bestTimes: parsed.bestTimes || {}, runHistory: parsed.runHistory || {} };
  }catch(e){
    return { completed:{}, bestTimes:{}, runHistory:{} };
  }
}
function saveProgress(){
  try{
    localStorage.setItem(PROGRESS_KEY, JSON.stringify({ completed: completedScenarios, bestTimes: bestTimes, runHistory: runHistory }));
  }catch(e){ /* stockage indisponible (navigation privée...), tant pis */ }
}

function pruneOrphanIds(obj){
  // évite qu'un id de scénario renommé/supprimé reste coincé en localStorage
  const validIds = Object.keys(SCENARIOS);
  Object.keys(obj).forEach(id => { if(!validIds.includes(id)) delete obj[id]; });
  return obj;
}

const RUN_HISTORY_MAX = 5;
const savedProgress = loadProgress();
const completedScenarios = pruneOrphanIds(savedProgress.completed);
const bestTimes = pruneOrphanIds(savedProgress.bestTimes);
const runHistory = pruneOrphanIds(savedProgress.runHistory);

function markScenarioComplete(scenarioId){
  completedScenarios[scenarioId] = true;
  saveProgress();
  updateHomeBadges();
}

function recordBestTime(scenarioId, elapsed){
  if(!bestTimes[scenarioId] || elapsed < bestTimes[scenarioId]){
    bestTimes[scenarioId] = elapsed;
  }
  if(!runHistory[scenarioId]) runHistory[scenarioId] = [];
  runHistory[scenarioId].push({ time: elapsed, date: new Date().toISOString() });
  runHistory[scenarioId].sort((a,b) => a.time - b.time);
  runHistory[scenarioId] = runHistory[scenarioId].slice(0, RUN_HISTORY_MAX);
  saveProgress();
  updateHomeBadges();
}

function resetProgress(){
  if(!confirm('Effacer ta progression sauvegardée (scénarios terminés, meilleurs temps, classement) ? Cette action est irréversible.')) return;
  Object.keys(completedScenarios).forEach(k => delete completedScenarios[k]);
  Object.keys(bestTimes).forEach(k => delete bestTimes[k]);
  Object.keys(runHistory).forEach(k => delete runHistory[k]);
  saveProgress();
  updateHomeBadges();
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
  showView('view-home');
  updateHomeBadges();
}

function scenarioDisplayName(sc){
  const parts = sc.tag.split('·');
  return parts[1] ? parts[1].trim() : sc.tag;
}

function showLeaderboard(){
  const ids = Object.keys(SCENARIOS);
  const host = document.getElementById('leaderboard-body');
  const totalRuns = ids.reduce((n, id) => n + (runHistory[id] ? runHistory[id].length : 0), 0);

  if(totalRuns === 0){
    host.innerHTML = `<p class="lb-empty">Aucune mission terminée pour l'instant. Termine un scénario pour apparaître ici — tes 5 meilleurs temps par scénario sont conservés.</p>`;
  } else {
    host.innerHTML = ids.map(id => {
      const sc = SCENARIOS[id];
      const runs = runHistory[id] || [];
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
  showView('view-leaderboard');
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
});
