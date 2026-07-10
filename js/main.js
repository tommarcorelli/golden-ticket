function showView(id){
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  window.scrollTo(0,0);
  const titles = {
    'view-home': 'Golden Ticket — Domain Breach Lab',
    'view-lesson': '📘 Leçon — Golden Ticket',
    'view-game': '🎫 Mission en cours — Golden Ticket',
    'view-glossary': '📖 Glossaire — Golden Ticket',
    'view-explain': '🛡️ Analyse — Golden Ticket'
  };
  document.title = titles[id] || 'Golden Ticket';
}

let lessonScenarioId = 'kerberoast';
let currentSlide = 0;
const completedScenarios = {};

function markScenarioComplete(scenarioId){
  completedScenarios[scenarioId] = true;
  updateHomeBadges();
}

const bestTimes = {};
function recordBestTime(scenarioId, elapsed){
  if(!bestTimes[scenarioId] || elapsed < bestTimes[scenarioId]){
    bestTimes[scenarioId] = elapsed;
  }
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
    track.innerHTML = `<span class="pt-fill">${done}</span> / ${ids.length} scénario${ids.length>1?'s':''} complété${done>1?'s':''} cette session`;
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
