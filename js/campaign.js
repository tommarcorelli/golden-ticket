// ═══════════════════════════════════════════════════════════
// Mode Campagne — un engagement red team complet, enchaînant des
// scénarios déjà existants dans un ordre imposé, avec un fil narratif.
// Ne crée AUCUN nouvel état persistant : le déblocage d'une étape se
// déduit simplement de `completedScenarios` (déjà en localStorage).
// Rejouer un scénario en dehors de la campagne compte quand même —
// c'est la même progression partout dans le jeu.
// ═══════════════════════════════════════════════════════════

const CAMPAIGNS = [
  {
    id:'campaign_infiltration',
    title:'Compromission complète — CORP.LOCAL',
    icon:'🎖️',
    intro:"Un engagement red team du premier accès jusqu'à la compromission totale du domaine. Chaque étape réutilise une technique déjà vue en scénario isolé — mais enchaînée, sans filet.",
    steps:[
      { id:'kerberoast', day:'Jour 1', brief:"Premier accès. Tu n'as qu'un compte standard. Trouve un point d'entrée par un compte de service mal protégé." },
      { id:'pth',         day:'Jour 2', brief:"Un hash récupéré la veille traîne encore en mémoire quelque part. Rebondis sur un autre serveur sans jamais connaître le mot de passe en clair." },
      { id:'acl',         day:'Jour 3', brief:"L'accès obtenu donne des droits oubliés sur un autre compte. Une ACL mal configurée, et c'est un nouveau maillon de la chaîne." },
      { id:'shadowcred',  day:'Jour 4', brief:"Plus subtil : un droit d'écriture étroit sur un attribut d'authentification, jamais audité. Prends la main sans jamais toucher un mot de passe." },
      { id:'dcsync',      day:'Jour 5', brief:"Dernière étape. Un compte de service a gardé des droits de réplication du domaine. Fais-toi passer pour un contrôleur — et prends le domaine entier." }
    ],
    achievementId:'campaign_finisher'
  }
];

function campaignStepStatus(campaign, index){
  if(completedScenarios[campaign.steps[index].id]) return 'done';
  if(index === 0) return 'unlocked';
  return completedScenarios[campaign.steps[index-1].id] ? 'unlocked' : 'locked';
}

function showCampaignView(){
  renderCampaignView();
  showView('view-campaign');
}

function renderCampaignView(){
  const host = document.getElementById('campaign-track');
  if(!host) return;
  host.innerHTML = CAMPAIGNS.map(camp => {
    const doneCount = camp.steps.filter(s => completedScenarios[s.id]).length;
    const finished = doneCount === camp.steps.length;
    const stepsHtml = camp.steps.map((step, i) => {
      const status = campaignStepStatus(camp, i);
      const sc = SCENARIOS[step.id];
      const name = sc ? scenarioDisplayName(sc) : step.id;
      const icon = status === 'done' ? '✓' : (status === 'locked' ? '🔒' : '▶');
      const actionBtn = status === 'locked'
        ? `<span class="cs-locked-tag">Terminer l'étape précédente pour débloquer</span>`
        : `<button class="mode-play" onclick="goToLesson('${step.id}')">${status === 'done' ? '↺ Rejouer' : '▶ Lancer'}</button>`;
      return `<div class="campaign-step ${status}">
        <div class="cs-marker" aria-hidden="true">${icon}</div>
        <div class="cs-body">
          <div class="cs-head"><span class="cs-day">${step.day}</span><h4>${name}</h4></div>
          <p class="cs-brief">${step.brief}</p>
          ${actionBtn}
        </div>
      </div>`;
    }).join('<div class="cs-connector" aria-hidden="true"></div>');

    return `<div class="campaign-block">
      <div class="campaign-head">
        <span class="campaign-icon">${camp.icon}</span>
        <div>
          <h3>${camp.title}${finished ? ' <span class="cs-finished-tag">✓ Terminée</span>' : ''}</h3>
          <p class="campaign-intro">${camp.intro}</p>
          <p class="campaign-progress">${doneCount} / ${camp.steps.length} étapes terminées</p>
        </div>
      </div>
      ${stepsHtml}
    </div>`;
  }).join('');
}

// Appelé depuis unlockAchievements() (progress.js) après chaque mission terminée.
function checkCampaignAchievements(unlockFn){
  CAMPAIGNS.forEach(camp => {
    if(camp.steps.every(s => completedScenarios[s.id])) unlockFn(camp.achievementId);
  });
}
