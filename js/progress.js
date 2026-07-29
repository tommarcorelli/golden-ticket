// ---------- progression persistante (localStorage) ----------
const PROGRESS_KEY = 'goldenticket_progress_v1';

function loadProgress(){
  try{
    const raw = localStorage.getItem(PROGRESS_KEY);
    if(!raw) return { completed:{}, bestTimes:{}, runHistory:{}, achievements:{}, librePaths:{}, blueteamCases:{}, quizPassed:{} };
    const parsed = JSON.parse(raw);
    return {
      completed: parsed.completed || {},
      bestTimes: parsed.bestTimes || {},
      runHistory: parsed.runHistory || {},
      achievements: parsed.achievements || {},
      librePaths: parsed.librePaths || {},
      blueteamCases: parsed.blueteamCases || {},
      quizPassed: parsed.quizPassed || {}
    };
  }catch(e){
    return { completed:{}, bestTimes:{}, runHistory:{}, achievements:{}, librePaths:{}, blueteamCases:{}, quizPassed:{} };
  }
}
function saveProgress(){
  try{
    localStorage.setItem(PROGRESS_KEY, JSON.stringify({
      completed: completedScenarios, bestTimes: bestTimes, runHistory: runHistory,
      achievements: achievements, librePaths: librePaths, blueteamCases: blueteamCases,
      quizPassed: quizPassed
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
const blueteamCases = savedProgress.blueteamCases;
const quizPassed = pruneOrphanIds(savedProgress.quizPassed);
const QUIZ_SCENARIOS = ['kerberoast','pth','acl','azuread','adcs','shadowcred','dcsync','unconstrained','breakglass','gpo','goldenticket','hybridbridge'];

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
  Object.keys(blueteamCases).forEach(k => delete blueteamCases[k]);
  Object.keys(quizPassed).forEach(k => delete quizPassed[k]);
  saveProgress();
  updateHomeBadges();
}

// ---------- succès ----------
const ACHIEVEMENTS = [
  { id:'no_hint',       icon:'🎯', title:'Sans indice',    desc:"Terminer une mission sans cliquer sur Indice" },
  { id:'speedster',     icon:'⚡', title:'Éclair',          desc:"Terminer une mission en moins de 45s" },
  { id:'curious',       icon:'🧠', title:'Curieux',         desc:"Consulter man au moins 3 fois dans une mission" },
  { id:'all_routes',    icon:'🧭', title:'Toutes les routes', desc:"Terminer le Mode Libre par ses 3 chemins différents (Helpdesk, Pass-the-Hash, Server Admins)" },
  { id:'golden_finisher',icon:'👑', title:'Golden Ticket',  desc:"Terminer le Chapitre Final" },
  { id:'hybrid_finisher',icon:'🌉', title:'Pont Hybride',  desc:"Terminer le Chapitre Final II" },
  { id:'domain_master', icon:'🏆', title:'Maître du domaine', desc:"Terminer tous les scénarios" },
  { id:'ghost',         icon:'🥷', title:'Fantôme',          desc:"Terminer une mission sans jamais déclencher l'alerte SOC" },
  { id:'blueteam_detective', icon:'🕵️', title:'Détective complet', desc:"Résoudre les 5 dossiers d'incident différents du Mode Blue Team" },
  { id:'quiz_master', icon:'📚', title:'Théoricien', desc:"Réussir sans faute le quiz de défense de tous les scénarios techniques" },
];

function recordQuizPass(scenarioId){
  if(!QUIZ_SCENARIOS.includes(scenarioId)) return null;
  quizPassed[scenarioId] = true;
  let unlocked = null;
  if(!achievements['quiz_master'] && QUIZ_SCENARIOS.every(id => quizPassed[id])){
    achievements['quiz_master'] = { date: new Date().toISOString() };
    unlocked = ACHIEVEMENTS.find(a => a.id === 'quiz_master');
  }
  saveProgress();
  return unlocked;
}

function unlockAchievements({ scenarioId, elapsed, hintsUsed, manCount, pathTaken, blueteamCaseId, opsecEnabled, detected }){
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
  if(scenarioId === 'hybridbridge') unlock('hybrid_finisher');
  if(opsecEnabled && !detected) unlock('ghost');

  if(scenarioId === 'libre' && pathTaken){
    librePaths[pathTaken] = true;
    if(librePaths['pth'] && librePaths['acl-helpdesk'] && librePaths['acl-serveradmins']) unlock('all_routes');
  }

  if(scenarioId === 'blueteam' && blueteamCaseId){
    blueteamCases[blueteamCaseId] = true;
    const allCaseIds = SCENARIOS.blueteam && SCENARIOS.blueteam.CASES ? SCENARIOS.blueteam.CASES.map(c => c.id) : [];
    if(allCaseIds.length && allCaseIds.every(id => blueteamCases[id])) unlock('blueteam_detective');
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
    achievements: achievements, librePaths: librePaths, blueteamCases: blueteamCases,
    quizPassed: quizPassed
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
      Object.keys(blueteamCases).forEach(k => delete blueteamCases[k]);
      Object.keys(quizPassed).forEach(k => delete quizPassed[k]);
      Object.assign(completedScenarios, pruneOrphanIds(data.completed || {}));
      Object.assign(bestTimes, pruneOrphanIds(data.bestTimes || {}));
      Object.assign(runHistory, pruneOrphanIds(data.runHistory || {}));
      Object.assign(achievements, data.achievements || {});
      Object.assign(librePaths, data.librePaths || {});
      Object.assign(blueteamCases, data.blueteamCases || {});
      Object.assign(quizPassed, pruneOrphanIds(data.quizPassed || {}));
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
