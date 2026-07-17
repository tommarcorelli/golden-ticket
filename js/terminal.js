// ═══════════════════════════════════════════════════════════
// Moteur générique — commun à tous les scénarios.
// Les données/commandes spécifiques vivent dans scenarios.js (SCENARIOS).
// ═══════════════════════════════════════════════════════════

let state = { scenarioId:'kerberoast', user:null, objDone:{}, extra:{}, hintLevel:{} };
let cmdHistory = [];
let historyIndex = -1;
let missionStart = null;
let cmdCount = 0;
let hintsUsed = 0;
let manCount = 0;

const commonManPages = {
  'whoami': { name:'whoami /priv', role:'Affiche ton identité et tes droits actuels',
    explain:"Montre le compte avec lequel tu es connecté, son rôle et ses groupes.",
    usage:'whoami /priv' },
  'dir': { name:'dir', role:'Liste le contenu du dossier courant',
    explain:"Équivalent Windows de 'ls'. Les droits affichés dépendent du compte avec lequel tu es connecté.",
    usage:'dir' },
  'type': { name:'type', role:"Affiche le contenu d'un fichier",
    explain:"Équivalent Windows de 'cat'. Refusé si ton compte actuel n'a pas les droits de lecture sur le fichier.",
    usage:'type <fichier>' }
};

const screen = () => document.getElementById('screen');
function currentScenario(){ return SCENARIOS[state.scenarioId]; }

function print(html){
  const div = document.createElement('div');
  div.innerHTML = html;
  screen().appendChild(div);
  screen().scrollTop = screen().scrollHeight;
  if(html.indexOf('out-bad') !== -1) playBuzzSound();
}
function escapeHtml(s){
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function printCmd(text){
  const label = currentScenario().identities[state.user].label;
  print(`<span class="prompt-user">${label}</span><span class="prompt-path">&gt; </span><span class="line-cmd">${escapeHtml(text)}</span>`);
}
function updatePrompt(){
  document.getElementById('prompt-label').textContent = `${currentScenario().identities[state.user].label}>`;
}

function renderObjectives(){
  const el = document.getElementById('objectives');
  if(!el) return;
  el.innerHTML = currentScenario().objectives.map(o => {
    const done = !!state.objDone[o.id];
    return `<div class="obj ${done?'done':''}" role="listitem"><span class="mark" aria-hidden="true">${done?'✓':'○'}</span><span class="sr-only">${done?'Terminé : ':'À faire : '}</span><span class="txt">${o.text}</span></div>`;
  }).join('');
}
function complete(id){
  if(!state.objDone[id]){
    state.objDone[id] = true;
    renderObjectives();
    const t = document.getElementById('hint-text');
    const dotsEl = document.getElementById('hint-dots');
    const btn = document.getElementById('hint-btn');
    if(t) t.style.display = 'none';
    if(dotsEl) dotsEl.innerHTML = '';
    if(btn) btn.textContent = '💡 Indice';
  }
}
function showHint(){
  if(state.expertMode) return;
  const sc = currentScenario();
  const t = document.getElementById('hint-text');
  const stageIdx = Math.min(Object.values(state.objDone).filter(Boolean).length, sc.hints.length - 1);
  const tiers = sc.hints[stageIdx];
  const level = state.hintLevel[stageIdx] || 0;
  hintsUsed++;
  t.textContent = tiers[level];
  t.style.display = 'block';
  const dotsEl = document.getElementById('hint-dots');
  if(dotsEl){
    dotsEl.innerHTML = tiers.map((_,i) => `<span class="${i<=level?'on':''}"></span>`).join('');
  }
  const btn = document.getElementById('hint-btn');
  if(level < tiers.length - 1){
    state.hintLevel[stageIdx] = level + 1;
    if(btn) btn.textContent = '💡 Indice plus précis';
  } else if(btn){
    btn.textContent = '💡 Indice';
  }
}

function renderOpsecGauge(){
  const fill = document.getElementById('opsec-bar-fill');
  const status = document.getElementById('opsec-status');
  if(!fill || !status) return;
  const level = (state.opsec && state.opsec.level) || 0;
  fill.style.width = level + '%';
  fill.classList.toggle('warn', level >= 40 && level < 100);
  fill.classList.toggle('danger', level >= 100);
  if(state.opsec && state.opsec.detected){
    status.textContent = '🚨 Détecté par le SOC — la mission continue, mais tu n\'es plus furtif.';
    status.classList.add('opsec-detected');
  } else if(level >= 40){
    status.textContent = `⚠️ Activité suspecte remontée (${level}%)`;
    status.classList.remove('opsec-detected');
  } else {
    status.textContent = level === 0 ? 'Aucune activité suspecte détectée' : `Niveau d'alerte : ${level}%`;
    status.classList.remove('opsec-detected');
  }
}

function addNoise(points, label){
  const sc = currentScenario();
  if(!sc.opsecEnabled || !state.opsec) return;
  if(state.opsec.detected) return;
  state.opsec.level = Math.min(100, state.opsec.level + points);
  renderOpsecGauge();
  if(state.opsec.level >= 100){
    state.opsec.detected = true;
    print(`<span class="out-bad">🚨 Alerte : l'équipe sécurité (SOC) a été notifiée — trop d'actions bruyantes d'affilée (${escapeHtml(label)}). La mission continue, mais ta présence est désormais surveillée.</span>`);
  }
}

function bootTerminal(scenarioId){
  if(scenarioId) state.scenarioId = scenarioId;
  const sc = currentScenario();
  screen().innerHTML = '';
  state.user = sc.startUser;
  state.objDone = {};
  state.hintLevel = {};
  state.extra = sc.initState ? sc.initState() : {};
  state.expertMode = (typeof expertMode !== 'undefined') ? expertMode : false;
  state.opsec = { level:0, detected:false };
  cmdHistory = [];
  historyIndex = -1;
  missionStart = Date.now();
  cmdCount = 0;
  hintsUsed = 0;
  manCount = 0;
  document.getElementById('screen').closest('.terminal').classList.remove('victory');
  const mc = document.getElementById('mission-complete');
  if(mc){ mc.classList.remove('show'); mc.classList.remove('epic'); mc.hidden = true; }
  document.removeEventListener('keydown', trapMcFocus);
  const achHost = document.getElementById('mc-achievements'); if(achHost) achHost.innerHTML = '';
  const ch = document.getElementById('confetti-host'); if(ch) ch.innerHTML = '';
  document.getElementById('game-tag').textContent = sc.tag + (state.expertMode ? '  🎓' : '');
  document.getElementById('cmd-ref-list').innerHTML = sc.cmdRefHtml;
  document.getElementById('hint-text').style.display = 'none';
  const hintDots = document.getElementById('hint-dots'); if(hintDots) hintDots.innerHTML = '';
  const hintBtn = document.getElementById('hint-btn');
  if(hintBtn){
    if(state.expertMode){
      hintBtn.textContent = '🚫 Indices désactivés (Mode Expert)';
      hintBtn.disabled = true;
      hintBtn.classList.add('disabled');
    } else {
      hintBtn.textContent = '💡 Indice';
      hintBtn.disabled = false;
      hintBtn.classList.remove('disabled');
    }
  }
  stopMissionTimer();
  const timerEl = document.getElementById('mission-timer');
  if(timerEl) timerEl.style.display = state.expertMode ? 'inline-block' : 'none';
  if(state.expertMode) startMissionTimer();
  const opsecCard = document.getElementById('opsec-card');
  if(opsecCard) opsecCard.style.display = sc.opsecEnabled ? 'block' : 'none';
  renderOpsecGauge();
  if(typeof AttackGraph !== 'undefined') AttackGraph.reset();
  renderObjectives();
  updatePrompt();
  sc.introLines.forEach(line => print(line));
  print('');
  document.getElementById('cmd-input').focus();
}

let missionTimerInterval = null;
function startMissionTimer(){
  const timerEl = document.getElementById('mission-timer');
  if(!timerEl) return;
  const tick = () => {
    const elapsed = Math.max(0, Math.round((Date.now() - missionStart) / 1000));
    const mm = Math.floor(elapsed / 60);
    const ss = String(elapsed % 60).padStart(2,'0');
    timerEl.textContent = `⏱ ${mm}:${ss}`;
  };
  tick();
  missionTimerInterval = setInterval(tick, 1000);
}
function stopMissionTimer(){
  if(missionTimerInterval){ clearInterval(missionTimerInterval); missionTimerInterval = null; }
}

function handle(raw){
  const cmd = raw.trim();
  if(cmd === '') return;
  printCmd(cmd);
  if(cmdHistory[cmdHistory.length-1] !== cmd) cmdHistory.push(cmd);
  historyIndex = cmdHistory.length;
  cmdCount++;
  const lower = cmd.toLowerCase();
  const sc = currentScenario();

  if(lower === 'help'){
    print(`<span class="out-info">Commandes disponibles :</span>`);
    print(`<span class="out-dim">${sc.helpLine}</span>`);
    print(`<span class="out-info">💡 Pas sûr de ce que fait une commande ? Tape <b>man &lt;commande&gt;</b>, ex : <b>man dir</b></span>`);
    return;
  }

  let m = lower.match(/^man (.+)$/);
  if(m){
    manCount++;
    const key = m[1].trim();
    const doc = (sc.manPages && sc.manPages[key]) || commonManPages[key];
    if(!doc){ print(`<span class="out-bad">Pas de page de manuel pour '${escapeHtml(key)}'.</span>`); return; }
    print(`<span class="out-info"><b>${doc.name}</b> — ${doc.role}</span>`);
    print(`<span class="out-dim">${doc.explain}</span>`);
    print(`<span class="out-warn">Usage : ${doc.usage}</span>`);
    return;
  }

  if(lower === 'clear' || lower === 'cls'){
    screen().innerHTML = '';
    return;
  }

  // délégation au scénario actif
  const handledByScenario = sc.handle(lower, cmd, m);
  if(sc.noiseRules){
    sc.noiseRules.forEach(rule => {
      if(rule.test(lower)) addNoise(rule.points, rule.label);
    });
  }
  if(handledByScenario) return;

  // easter eggs génériques
  if(lower === 'sudo make me a sandwich' || lower === 'make me a sandwich'){
    print(`<span class="out-good">🥪 Voilà.</span>`);
    return;
  }
  if(lower === 'sudo' || lower.startsWith('sudo ')){
    print(`<span class="out-bad">'sudo' n'existe pas sous Windows. Tu cherches sûrement <b>runas</b>.</span>`);
    return;
  }
  if(lower === 'ls'){
    print(`<span class="out-bad">Tu es sous Windows ici. La commande équivalente est <b>dir</b>.</span>`);
    return;
  }
  if(lower === 'cat' || lower.startsWith('cat ')){
    print(`<span class="out-bad">Sous Windows, c'est <b>type</b> et non 'cat'.</span>`);
    return;
  }
  if(lower === 'whoami is the best'){
    print(`<span class="out-good">🏆 Facile à dire, difficile à devenir Domain Admin.</span>`);
    return;
  }
  if(lower === 'matrix'){
    print(`<span class="out-info">Wake up, Neo...</span>`);
    triggerMatrixRain();
    return;
  }
  if(lower === 'iddqd'){
    print(`<span class="out-bad">Pas de mode invincible ici — même Domain Admin peut se faire détecter.</span>`);
    return;
  }
  if(lower === '42'){
    print(`<span class="out-info">La réponse à la grande question... mais pas au mot de passe krbtgt.</span>`);
    return;
  }

  print(`<span class="out-bad">'${escapeHtml(cmd)}' n'est pas reconnu comme commande.</span>`);
  print(`<span class="out-dim">💡 Tape <b>help</b> pour la liste des commandes, ou <b>man &lt;commande&gt;</b> pour une explication.</span>`);
}

function vibrate(pattern){
  try{ navigator.vibrate?.(pattern); }catch(e){ /* pas dispo, tant pis */ }
}

function triggerMatrixRain(){
  const term = document.querySelector('.terminal');
  if(!term || term.querySelector('.matrix-rain')) return;
  const canvas = document.createElement('canvas');
  canvas.className = 'matrix-rain';
  canvas.style.cssText = 'position:absolute;inset:0;z-index:5;pointer-events:none;border-radius:inherit;';
  if(getComputedStyle(term).position === 'static') term.style.position = 'relative';
  term.appendChild(canvas);
  const ctx = canvas.getContext('2d');
  const w = canvas.width = term.clientWidth;
  const h = canvas.height = term.clientHeight;
  const fontSize = 14;
  const cols = Math.floor(w / fontSize);
  const drops = new Array(cols).fill(0);
  const chars = 'アイウエオカキクケコサシスセソ0123456789ABCDEF';
  let frames = 0;
  const maxFrames = 110; // ~4-5s à 24fps
  const interval = setInterval(() => {
    ctx.fillStyle = 'rgba(5,4,8,0.18)';
    ctx.fillRect(0, 0, w, h);
    ctx.fillStyle = '#35d399';
    ctx.font = fontSize + 'px monospace';
    drops.forEach((y, i) => {
      const char = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(char, i * fontSize, y * fontSize);
      if(y * fontSize > h && Math.random() > 0.975) drops[i] = 0;
      else drops[i] = y + 1;
    });
    frames++;
    if(frames >= maxFrames){
      clearInterval(interval);
      canvas.style.transition = 'opacity .6s ease';
      canvas.style.opacity = '0';
      setTimeout(() => canvas.remove(), 600);
    }
  }, 40);
}

function finishMission(){
  stopMissionTimer();
  if(typeof markScenarioComplete === 'function') markScenarioComplete(state.scenarioId);
  playVictorySound();
  const sc = currentScenario();
  const elapsed = Math.max(1, Math.round((Date.now() - missionStart) / 1000));
  if(typeof recordBestTime === 'function') recordBestTime(state.scenarioId, elapsed, state.expertMode);
  let newAchievements = [];
  if(typeof unlockAchievements === 'function'){
    newAchievements = unlockAchievements({
      scenarioId: state.scenarioId, elapsed, hintsUsed, manCount,
      pathTaken: state.extra ? state.extra.pathTaken : null,
      opsecEnabled: !!sc.opsecEnabled, detected: !!(state.opsec && state.opsec.detected)
    });
  }
  if(sc.epic){
    playEpicFanfare();
    vibrate([40, 60, 40, 60, 140]);
    setTimeout(()=> showMissionComplete(elapsed, cmdCount, hintsUsed, newAchievements), 1300);
  } else {
    vibrate(50);
    setTimeout(()=> showMissionComplete(elapsed, cmdCount, hintsUsed, newAchievements), 900);
  }
}

function showMissionComplete(elapsed, cmds, hints, newAchievements){
  const sc = currentScenario();
  const overlay = document.getElementById('mission-complete');
  const card = overlay.querySelector('.mc-card');
  overlay.classList.toggle('epic', !!sc.epic);
  card.querySelector('.mc-badge').textContent = sc.epic ? '👑' : '🏆';
  document.getElementById('mc-title').textContent = sc.completeTitle;
  document.getElementById('mc-sub-text').textContent = sc.completeSub;
  document.getElementById('mc-chain').innerHTML = sc.chainSteps.map((s,i) =>
    (i > 0 ? '<div class="mc-arrow">→</div>' : '') + `<div class="mc-step">${s.icon}<span>${s.label}</span></div>`
  ).join('');
  lastMissionResult = {
    title: sc.completeTitle,
    chain: sc.chainSteps.map(s => s.icon).join(' → '),
    elapsed, cmds, hints,
    epic: !!sc.epic
  };
  const achHost = document.getElementById('mc-achievements');
  if(achHost){
    achHost.innerHTML = (newAchievements || []).map(a =>
      `<div class="mc-ach-toast"><span class="ach-icon">${a.icon}</span><span><b>Succès débloqué : ${a.title}</b> — ${a.desc}</span></div>`
    ).join('');
  }
  document.getElementById('mc-time').textContent = elapsed + 's';
  document.getElementById('mc-cmds').textContent = cmds;
  document.getElementById('mc-hints').textContent = hints;
  const opsecStat = document.getElementById('mc-opsec-stat');
  if(opsecStat){
    if(sc.opsecEnabled){
      opsecStat.style.display = '';
      document.getElementById('mc-opsec').textContent = state.opsec.detected ? '🚨 Détecté' : '🥷 Furtif';
    } else {
      opsecStat.style.display = 'none';
    }
  }
  const certBtn = document.getElementById('mc-cert-btn');
  if(certBtn) certBtn.style.display = sc.epic ? 'inline-block' : 'none';

  const confettiHost = document.getElementById('confetti-host');
  confettiHost.innerHTML = '';
  if(sc.epic){
    const pieces = ['🎫','👑','✨','🔑'];
    for(let i=0;i<36;i++){
      const span = document.createElement('span');
      span.className = 'confetti-piece';
      span.textContent = pieces[i % pieces.length];
      span.style.left = (Math.random()*100) + '%';
      span.style.animationDelay = (Math.random()*0.8) + 's';
      span.style.animationDuration = (2.4 + Math.random()*1.6) + 's';
      span.style.fontSize = (14 + Math.random()*14) + 'px';
      confettiHost.appendChild(span);
    }
    setTimeout(()=> { confettiHost.innerHTML = ''; }, 4200);
  }

  overlay.hidden = false;
  overlay.classList.add('show');
  mcReturnFocus = document.activeElement;
  card.focus({ preventScroll: true });
  document.addEventListener('keydown', trapMcFocus);
}
let mcReturnFocus = null;
function trapMcFocus(e){
  const overlay = document.getElementById('mission-complete');
  if(!overlay.classList.contains('show')) return;
  if(e.key === 'Escape'){ closeMissionComplete(); return; }
  if(e.key !== 'Tab') return;
  const focusables = overlay.querySelectorAll('button, [href], [tabindex]:not([tabindex="-1"])');
  if(!focusables.length) return;
  const first = focusables[0];
  const last = focusables[focusables.length - 1];
  if(e.shiftKey && document.activeElement === first){
    e.preventDefault(); last.focus();
  } else if(!e.shiftKey && document.activeElement === last){
    e.preventDefault(); first.focus();
  }
}
function closeMissionComplete(){
  const overlay = document.getElementById('mission-complete');
  overlay.classList.remove('show');
  overlay.classList.remove('epic');
  overlay.hidden = true;
  document.getElementById('confetti-host').innerHTML = '';
  document.removeEventListener('keydown', trapMcFocus);
  if(mcReturnFocus && document.body.contains(mcReturnFocus)) mcReturnFocus.focus();
}

function copyFlag(btn){
  const flag = currentScenario().flag;
  navigator.clipboard?.writeText(flag).then(()=>{
    btn.textContent = '✓ Copié';
    setTimeout(()=> btn.textContent = '📋 Copier', 1500);
  }).catch(()=>{});
}

let lastMissionResult = null;

function shareMissionResult(btn){
  if(!lastMissionResult) return;
  const r = lastMissionResult;
  const text = [
    `🎫 GOLDEN TICKET — ${r.title}`,
    r.chain,
    `⏱ ${r.elapsed}s · 💻 ${r.cmds} commandes · 💡 ${r.hints} indice${r.hints > 1 ? 's' : ''}`,
    `Fais mieux : ${location.href.split('#')[0].split('?')[0]}`
  ].join('\n');

  if(navigator.share){
    navigator.share({ text }).catch(()=>{ /* annulé par l'utilisateur, tant pis */ });
    return;
  }
  navigator.clipboard?.writeText(text).then(()=>{
    if(btn){
      const original = btn.textContent;
      btn.textContent = '✓ Copié dans le presse-papier';
      setTimeout(()=> btn.textContent = original, 1800);
    }
  }).catch(()=>{});
}

function playBuzzSound(){
  if(typeof soundFxEnabled !== 'undefined' && !soundFxEnabled) return;
  try{
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'square';
    const start = ctx.currentTime;
    osc.frequency.setValueAtTime(120, start);
    osc.frequency.exponentialRampToValueAtTime(75, start + 0.14);
    gain.gain.setValueAtTime(0.0001, start);
    gain.gain.exponentialRampToValueAtTime(0.045, start + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.16);
    osc.connect(gain).connect(ctx.destination);
    osc.start(start);
    osc.stop(start + 0.16);
  }catch(e){ /* audio non disponible, tant pis */ }
}

function playEpicFanfare(){
  if(typeof soundFxEnabled !== 'undefined' && !soundFxEnabled) return;
  try{
    const ctx2 = new (window.AudioContext || window.webkitAudioContext)();
    // un accord grave qui monte, puis l'arpège triomphal
    const bass = [130.81, 164.81, 196.00]; // C3 E3 G3
    bass.forEach((freq,i)=>{
      const osc = ctx2.createOscillator();
      const gain = ctx2.createGain();
      osc.type = 'sawtooth';
      osc.frequency.value = freq;
      const start = ctx2.currentTime;
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(0.05, start + 0.05);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.9);
      osc.connect(gain).connect(ctx2.destination);
      osc.start(start); osc.stop(start + 0.9);
    });
    const arp = [523.25, 659.25, 783.99, 1046.5, 1318.5]; // C5 E5 G5 C6 E6
    arp.forEach((freq,i)=>{
      const osc = ctx2.createOscillator();
      const gain = ctx2.createGain();
      osc.type = 'triangle';
      osc.frequency.value = freq;
      const start = ctx2.currentTime + 0.15 + i * 0.11;
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(0.14, start + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.35);
      osc.connect(gain).connect(ctx2.destination);
      osc.start(start); osc.stop(start + 0.35);
    });
  }catch(e){ /* audio non disponible, tant pis */ }
}

function playVictorySound(){
  if(typeof soundFxEnabled !== 'undefined' && !soundFxEnabled) return;
  try{
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const notes = [523.25, 659.25, 783.99, 1046.5]; // C5 E5 G5 C6
    notes.forEach((freq, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.value = freq;
      const start = ctx.currentTime + i * 0.09;
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(0.12, start + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.28);
      osc.connect(gain).connect(ctx.destination);
      osc.start(start);
      osc.stop(start + 0.3);
    });
  }catch(e){ /* audio non disponible, tant pis */ }
}

function initTerminalInput(){
  const input = document.getElementById('cmd-input');
  input.addEventListener('keydown', (e)=>{
    if(e.key === 'Enter'){
      handle(input.value);
      input.value = '';
    } else if(e.key === 'ArrowUp'){
      e.preventDefault();
      if(cmdHistory.length === 0) return;
      historyIndex = Math.max(0, historyIndex - 1);
      input.value = cmdHistory[historyIndex] || '';
    } else if(e.key === 'ArrowDown'){
      e.preventDefault();
      if(cmdHistory.length === 0) return;
      historyIndex = Math.min(cmdHistory.length, historyIndex + 1);
      input.value = cmdHistory[historyIndex] || '';
    } else if(e.key === 'Tab'){
      e.preventDefault();
      const val = input.value.toLowerCase();
      if(val === '') return;
      const matches = currentScenario().knownCommands.filter(c => c.startsWith(val));
      if(matches.length === 1){
        input.value = matches[0];
      } else if(matches.length > 1){
        print(`<span class="out-dim">${matches.join('   ')}</span>`);
      }
    }
  });
}
