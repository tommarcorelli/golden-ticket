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

// ---------- mode budget de commandes (préférence simple, séparée de la progression) ----------
// Nombre de commandes limité par mission (défini par scénario, voir cmdBudget dans js/scenarios/) —
// force à réfléchir avant de taper plutôt qu'à tâtonner. Sans effet sur le Mode Blue Team
// (pas de cmdBudget défini pour ce scénario, cf. terminal.js).
const BUDGET_KEY = 'goldenticket_budget_mode';
let budgetMode = false;
try{ budgetMode = localStorage.getItem(BUDGET_KEY) === '1'; }catch(e){ budgetMode = false; }

function toggleBudgetMode(){
  budgetMode = !budgetMode;
  try{ localStorage.setItem(BUDGET_KEY, budgetMode ? '1' : '0'); }catch(e){ /* tant pis */ }
  renderBudgetToggle();
}

function renderBudgetToggle(){
  const btn = document.getElementById('budget-toggle');
  const sw = document.getElementById('budget-switch');
  if(btn){ btn.classList.toggle('on', budgetMode); btn.setAttribute('aria-checked', budgetMode ? 'true' : 'false'); }
  if(sw){ sw.setAttribute('aria-checked', budgetMode ? 'true' : 'false'); }
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

document.addEventListener('DOMContentLoaded', () => {
  initTerminalInput();
  updateHomeBadges();
  renderExpertToggle();
  renderBudgetToggle();
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
