let quizState = { total:0, correct:0, answered:0 };

function showExplain(){
  const sc = SCENARIOS[state.scenarioId];
  document.getElementById('explain-tag').textContent = `🛡️ ANALYSE · ${sc.tag.split('·')[1] ? sc.tag.split('·')[1].trim() : sc.tag}`;
  document.getElementById('explain-title').textContent = 'Pourquoi ça marche';
  document.getElementById('explain-why').textContent = sc.deepDive.why;
  const mitreHost = document.getElementById('explain-mitre');
  if(mitreHost){
    const mitre = sc.deepDive.mitre;
    if(mitre && mitre.length){
      mitreHost.style.display = '';
      mitreHost.innerHTML = mitre.map(m =>
        `<a class="mitre-chip" href="https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/" target="_blank" rel="noopener" title="${m.name}"><span class="mitre-id">${m.id}</span> ${m.name}</a>`
      ).join('');
    } else {
      mitreHost.style.display = 'none';
      mitreHost.innerHTML = '';
    }
  }
  document.getElementById('explain-defenses').innerHTML = sc.deepDive.defenses.map(d => `<li>${d}</li>`).join('');
  renderQuiz(sc);
  showView('view-explain');
}

function renderQuiz(sc){
  const host = document.getElementById('explain-quiz');
  if(!host) return;
  const quiz = sc.deepDive.quiz;
  if(!quiz || !quiz.length){
    host.style.display = 'none';
    host.innerHTML = '';
    return;
  }
  host.style.display = '';
  quizState = { total: quiz.length, correct: 0, answered: 0 };
  host.innerHTML = `<h3 class="defense-heading">🧠 Quiz éclair</h3>` +
    quiz.map((q, qi) => `
      <div class="quiz-item" id="quiz-item-${qi}">
        <p class="quiz-q">${qi + 1}. ${q.q}</p>
        <div class="quiz-options">
          ${q.options.map((opt, oi) => `<button type="button" class="quiz-opt" onclick="answerQuiz(${qi},${oi})">${opt}</button>`).join('')}
        </div>
        <p class="quiz-feedback" id="quiz-feedback-${qi}" style="display:none;"></p>
      </div>
    `).join('') +
    `<div id="quiz-result" class="quiz-result" style="display:none;"></div>`;
}

function answerQuiz(qi, oi){
  const sc = SCENARIOS[state.scenarioId];
  const quiz = sc.deepDive.quiz;
  if(!quiz || !quiz[qi]) return;
  const q = quiz[qi];
  const item = document.getElementById('quiz-item-' + qi);
  if(!item || item.classList.contains('answered')) return;
  item.classList.add('answered');

  const buttons = item.querySelectorAll('.quiz-opt');
  buttons.forEach((b, idx) => {
    b.disabled = true;
    if(idx === q.correct) b.classList.add('correct');
    else if(idx === oi) b.classList.add('incorrect');
  });

  const isCorrect = oi === q.correct;
  if(isCorrect) quizState.correct++;
  quizState.answered++;

  if(isCorrect){
    if(typeof playDingSound === 'function') playDingSound();
    if(typeof vibrate === 'function') vibrate(30);
  } else {
    if(typeof playBuzzSound === 'function') playBuzzSound();
    if(typeof vibrate === 'function') vibrate([20, 40, 20]);
  }

  const fb = document.getElementById('quiz-feedback-' + qi);
  if(fb){
    fb.style.display = '';
    fb.innerHTML = `<span class="${isCorrect ? 'quiz-verdict-ok' : 'quiz-verdict-ko'}">${isCorrect ? '✔ Exact.' : '✘ Pas tout à fait.'}</span> ${q.explain}`;
  }

  if(quizState.answered === quizState.total){
    const resultHost = document.getElementById('quiz-result');
    if(!resultHost) return;
    resultHost.style.display = '';
    let unlocked = null;
    if(quizState.correct === quizState.total && typeof recordQuizPass === 'function'){
      unlocked = recordQuizPass(state.scenarioId);
      if(typeof playVictorySound === 'function') playVictorySound();
    }
    resultHost.innerHTML = `<div class="quiz-score">Score : ${quizState.correct}/${quizState.total}</div>` +
      (unlocked ? `<div class="mc-ach-toast"><span class="ach-icon">${unlocked.icon}</span><span><b>Succès débloqué : ${unlocked.title}</b> — ${unlocked.desc}</span></div>` : '');
    if(typeof renderAchievementsGrid === 'function') renderAchievementsGrid();
  }
}
