
// ---------------------------------------------------------
// SCÉNARIO 09 — CONTOURNEMENT DE CONDITIONAL ACCESS (COMPTE DE SECOURS)
// ---------------------------------------------------------
SCENARIOS.breakglass = {
  id:'breakglass',
  tag:'🚨 SCÉNARIO 09 · CONTOURNEMENT CONDITIONAL ACCESS',
  lessonTag:'📘 LEÇON · SCÉNARIO 09',
  opsecEnabled:true,
  noiseRules:[NOISE.caPolicyEnum, NOISE.mgUserLookup, NOISE.passwordSpray, NOISE.connectMguser],
  startUser:'p.giraud',

  identities:{
    'p.giraud':          { label:'corp.onmicrosoft.com\\p.giraud', priv:'Utilisateur standard (Membre)', groups:['Users'], desc:'Employé — support informatique' },
    'breakglass.admin':  { label:'corp.onmicrosoft.com\\breakglass.admin', priv:'Compte de secours (break-glass) — Global Administrator permanent', groups:['Global Administrator'],
                           desc:"Compte créé pour reprendre la main en cas de panne du fournisseur d'identité fédéré. Volontairement exclu de toutes les politiques Conditional Access (y compris l'exigence de MFA), pour ne jamais risquer de bloquer un accès d'urgence. Mot de passe défini à la création en 2019, jamais changé depuis." }
  },

  CA_POLICIES:{
    'require-mfa-all-users':   { name:'Exiger MFA pour tous les utilisateurs', target:'Tous les utilisateurs', excludes:['breakglass.admin'] },
    'block-legacy-auth':       { name:"Bloquer les protocoles d'authentification hérités", target:'Tous les utilisateurs', excludes:[] },
    'require-compliant-device':{ name:'Exiger un appareil conforme pour les rôles admin', target:'Rôles d\'administration', excludes:['breakglass.admin'] }
  },

  sprayedPassword:'Secours2019!',

  objectives:[
    { id:'enum',    text:"Repérer un compte exclu des politiques Conditional Access" },
    { id:'discover',text:'Identifier ce compte comme un compte de secours (break-glass) à privilèges permanents' },
    { id:'spray',   text:"Retrouver son mot de passe (jamais changé, non protégé par MFA)" },
    { id:'auth',    text:"S'authentifier en tant que ce compte de secours" },
    { id:'flag',    text:'Récupérer le secret du coffre réservé aux Global Admins' },
  ],

  hints:[
    ["Un tableau de bord de conformité interne, mal restreint, laisse les politiques Conditional Access lisibles à tout employé.",
     "Il existe une commande pour lister les politiques Conditional Access du tenant et leurs exclusions.",
     "Liste les politiques avec `get-capolicies` — regarde attentivement la colonne des exclusions."],
    ["Un même compte revient dans plusieurs exclusions. Ce n'est probablement pas un hasard.",
     "Regarde le détail de ce compte : à quoi sert-il, et quel rôle d'annuaire possède-t-il ?",
     "Regarde le détail du compte exclu avec `get-mguser breakglass.admin` — c'est un compte de secours avec le rôle Global Administrator en permanence."],
    ["Ce compte n'a jamais MFA à passer, puisqu'il est exclu de toutes les politiques qui l'exigeraient. Reste à trouver son mot de passe.",
     "Un mot de passe jamais changé depuis des années est souvent un mot de passe faible ou commun. Il existe un outil pour essayer une liste de mots de passe courants sur un compte.",
     "Lance une attaque par pulvérisation de mots de passe : `invoke-passwordspray -user breakglass.admin -wordlist common`"],
    ["Tu as maintenant un mot de passe en clair pour ce compte.",
     "Connecte-toi en tant que ce compte avec la commande d'authentification habituelle.",
     "Authentifie-toi : `connect-mguser -user breakglass.admin -password Secours2019!`"],
    ["Ce compte a les pleins pouvoirs sur l'annuaire, en permanence, sans jamais avoir eu à prouver son identité par MFA.",
     "Un coffre de secrets réservé aux Global Admins est probablement accessible maintenant.",
     "Regarde le coffre avec `dir` puis `type flag.txt`."]
  ],

  manPages:{
    'get-capolicies': { name:'get-capolicies', role:'Liste les politiques Conditional Access du tenant',
      explain:"Chaque politique Conditional Access s'applique à une cible (utilisateurs, rôles) mais peut comporter des <b>exclusions</b> — des comptes volontairement épargnés, le plus souvent pour ne jamais se retrouver bloqué en cas de panne. Un compte qui revient dans plusieurs exclusions mérite d'être creusé.",
      usage:'get-capolicies' },
    'get-mguser': { name:'get-mguser', role:"Affiche le détail d'un compte utilisateur Entra ID",
      explain:"Montre le rôle d'annuaire, la description et le statut d'un compte. Un compte de <b>secours (break-glass)</b> est censé rester exceptionnel et surveillé de près — mais dans la pratique, il est souvent créé une fois, puis oublié.",
      usage:'get-mguser <nom>' },
    'invoke-passwordspray': { name:'invoke-passwordspray', role:'Essaie une liste de mots de passe courants sur un compte',
      explain:"Contre un compte normal, une politique Conditional Access exigeant le MFA arrêterait net cette attaque même avec le bon mot de passe. Un compte <b>exclu</b> de cette politique n'a aucun filet de sécurité : le mot de passe seul suffit.",
      usage:'invoke-passwordspray -user <nom> -wordlist <liste>' },
    'connect-mguser': { name:'connect-mguser', role:'Authentifie une session avec un compte utilisateur et son mot de passe',
      explain:"Authentification classique nom d'utilisateur + mot de passe — sans challenge supplémentaire pour un compte exclu des politiques Conditional Access qui l'exigeraient normalement.",
      usage:'connect-mguser -user <nom> -password <mot_de_passe>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'get-capolicies','get-mguser ',
    'invoke-passwordspray -user breakglass.admin -wordlist common',
    'connect-mguser -user breakglass.admin -password ','dir','type '
  ],

  helpLine:"whoami /priv, get-capolicies, get-mguser &lt;nom&gt;, invoke-passwordspray -user &lt;nom&gt; -wordlist &lt;liste&gt;, connect-mguser -user &lt;nom&gt; -password &lt;mdp&gt;, dir, type &lt;fichier&gt;, clear",

  cmdRefHtml:`whoami /priv<br>get-capolicies<br>get-mguser &lt;nom&gt;<br>invoke-passwordspray -user &lt;nom&gt; -wordlist &lt;liste&gt;<br>connect-mguser -user &lt;nom&gt; -password &lt;mdp&gt;<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Azure Cloud Shell [Simulation Entra ID Lab]</span>`,
    `<span class="out-dim">Connecté en tant que p.giraud@corp.onmicrosoft.com</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🚨', title:'Le compte de secours (break-glass)', html:
      `<p>Un tenant Entra ID dépend souvent d'un fournisseur d'identité fédéré ou d'exigences MFA strictes. Pour ne jamais se retrouver totalement bloqué en cas de panne, on crée un <b>compte de secours</b> — volontairement <b>exclu de toutes les politiques Conditional Access</b>, y compris le MFA.</p>
       <p>C'est une pratique recommandée... à condition qu'il soit étroitement surveillé. Le problème : il est souvent créé une fois, testé, puis <b>oublié</b>.</p>` },
    { icon:'🛡️', title:'Conditional Access : la politique, pas la porte', html:
      `<p>Le Conditional Access impose des conditions (MFA, appareil conforme...) selon qui se connecte et d'où. Mais une politique ne protège que les comptes qu'elle <b>cible réellement</b> — un compte listé en exclusion continue de s'authentifier avec un simple mot de passe, comme si la politique n'existait pas pour lui.</p>
       <p>Une exclusion légitime au départ (ne pas bloquer l'accès d'urgence) devient un angle mort permanent si personne ne la réévalue.</p>` },
    { icon:'🔑', title:"L'attaque : mot de passe oublié, jamais protégé", html:
      `<p>Un compte de secours créé une fois et jamais utilisé depuis n'a <b>aucune raison de changer de mot de passe</b> — et personne n'y pense, puisqu'il ne sert (presque) jamais. Sans MFA pour le protéger, une simple pulvérisation de mots de passe courants suffit.</p>
       <p>Résultat : un compte pensé comme un filet de sécurité devient la porte la plus fragile du tenant.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>p.giraud</b>, employé standard sur <b>corp.onmicrosoft.com</b>. Un tableau de bord de conformité mal restreint expose les politiques Conditional Access du tenant. Trouve le compte qui y échappe, et vois ce que son mot de passe oublié te permet.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Compte de secours compromis',
  completeSub:"Une exclusion Conditional Access oubliée, et voilà le Global Admin permanent obtenu.",
  chainSteps:[
    {icon:'🔎', label:'Exclusion repérée'}, {icon:'🚨', label:'Compte de secours identifié'},
    {icon:'🔑', label:'Mot de passe trouvé'}, {icon:'☁️', label:'Global Admin'}
  ],
  flag:'FLAG{entra_conditional_access_breakglass_bypass}',

  graph:{
    nodes:[
      { id:'p.giraud', label:'p.giraud', type:'user' },
      { id:'ca_mfa', label:'CA: Exiger MFA', type:'group' },
      { id:'breakglass', label:'breakglass.admin', type:'admin' }
    ],
    edges:[
      { id:'e_exclusion', from:'ca_mfa', to:'breakglass', type:'abuse', label:'Exclu de la politique (oublié)' },
      { id:'e_spray', from:'p.giraud', to:'breakglass', type:'auth', label:'Password spray (sans MFA)' },
      { id:'e_owned', from:'p.giraud', to:'breakglass', type:'owned', label:'Authentifié' }
    ]
  },

  deepDive:{
    mitre:[{id:'T1078.004', name:"Valid Accounts: Cloud Accounts"}, {id:'T1110.003', name:"Brute Force: Password Spraying"}],
    why:"Un compte de secours (break-glass) exclu des politiques Conditional Access est une pratique recommandée pour éviter un verrouillage total du tenant. Le risque n'est pas l'exclusion elle-même, mais son oubli : un compte jamais utilisé, jamais réévalué, garde un mot de passe défini à sa création et ne bénéficie d'aucune des protections (MFA, appareil conforme) qui s'appliquent à tous les autres comptes à privilèges. Un simple password spray suffit alors à le compromettre, sans déclencher le moindre challenge — la politique de sécurité la plus stricte du tenant ne s'applique tout simplement pas à lui.",
    defenses:[
      "Limiter à deux comptes de secours au maximum, avec des mots de passe longs, aléatoires et générés à la création — jamais mémorisables",
      "Surveiller étroitement toute connexion sur un compte de secours (alerte immédiate, quel que soit le moment) puisqu'il ne devrait quasiment jamais servir",
      "Réévaluer périodiquement la liste des comptes exclus de chaque politique Conditional Access — une exclusion doit rester une exception documentée, pas un oubli",
      "Protéger les comptes de secours par une clé de sécurité physique (FIDO2) plutôt que par mot de passe seul, quand le scénario de panne du fournisseur d'identité le permet"
    ],
    quiz:[
      { q:"Pourquoi un compte de secours (break-glass) est-il volontairement exclu des politiques Conditional Access ?",
        options:["Pour économiser des licences Entra ID","Pour ne jamais risquer de bloquer l'accès d'urgence en cas de panne du fournisseur d'identité","Parce que les comptes de service ne peuvent pas avoir de MFA","C'est une erreur de configuration, jamais volontaire"],
        correct:1,
        explain:"C'est une pratique reconnue : garantir qu'au moins un compte permette de reprendre la main même si le mécanisme d'authentification habituel (fédération, MFA) tombe en panne." },
      { q:"Qu'est-ce qui rend ce compte de secours vulnérable au password spray dans ce scénario ?",
        options:["Il est exclu des politiques Conditional Access qui exigeraient un MFA, et son mot de passe n'a jamais été changé","Il n'a aucun rôle d'annuaire particulier","Il est protégé par une clé de sécurité physique","Le password spray ne fonctionne jamais sur les comptes cloud"],
        correct:0,
        explain:"Sans MFA pour le protéger et avec un mot de passe jamais renouvelé depuis sa création, un simple essai de mots de passe courants suffit — aucun filet de sécurité ne s'applique à ce compte." },
      { q:"Quelle mesure protège le mieux un compte de secours sans compromettre sa disponibilité en cas de panne ?",
        options:["Une clé de sécurité physique (FIDO2) plutôt qu'un mot de passe seul, avec surveillance étroite de toute connexion","Le supprimer complètement, quitte à risquer un verrouillage total","Partager son mot de passe entre plusieurs administrateurs par email","Le renommer régulièrement sans changer le mot de passe"],
        correct:0,
        explain:"Une clé physique élimine le risque de mot de passe faible tout en restant utilisable si le fournisseur d'identité fédéré tombe en panne — combinée à une alerte immédiate sur toute connexion, puisque ce compte ne devrait presque jamais servir." }
    ]
  },

  initState(){ return { sprayed:false }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.breakglass;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Identité : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Rôles d'annuaire : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'get-capolicies'){
      print(`<span class="out-info">Politiques Conditional Access du tenant corp.onmicrosoft.com :</span>`);
      Object.values(sc.CA_POLICIES).forEach(p => {
        if(p.excludes.length){
          print(`<span class="out-warn">  ${p.name} — Cible : ${p.target} — Exclusion : ${p.excludes.join(', ')} ⚠</span>`);
        } else {
          print(`<span class="out-dim">  ${p.name} — Cible : ${p.target} — Exclusion : aucune</span>`);
        }
      });
      print(`<span class="out-dim">💡 Un même compte revient dans plusieurs exclusions — regarde son détail avec get-mguser.</span>`);
      AttackGraph.reveal({ nodes:['p.giraud','ca_mfa'], edges:['e_exclusion'] });
      complete('enum');
      return true;
    }

    m = lower.match(/^get-mguser (\S+)$/);
    if(m){
      const name = m[1];
      const u = sc.identities[name];
      if(!u){ print(`<span class="out-bad">Compte introuvable : ${escapeHtml(name)}</span>`); return true; }
      print(`<span class="out-info">Nom du compte : ${name}</span>`);
      print(`<span class="out-info">Description : ${u.desc}</span>`);
      print(`<span class="out-info">Rôles d'annuaire : ${u.groups.join(', ')}</span>`);
      if(name === 'breakglass.admin'){
        print(`<span class="out-warn">⚠ Compte de secours à privilèges permanents (Global Administrator), exclu de toutes les politiques Conditional Access — jamais réévalué depuis sa création.</span>`);
        AttackGraph.reveal({ nodes:['breakglass'] });
        complete('discover');
      }
      return true;
    }

    m = lower.match(/^invoke-passwordspray -user (\S+) -wordlist (\S+)$/);
    if(m){
      const target = m[1];
      if(target !== 'breakglass.admin'){
        print(`<span class="out-bad">${escapeHtml(target)} est probablement protégé par MFA — la pulvérisation ne suffira pas contre ce compte.</span>`);
        return true;
      }
      print(`<span class="out-info">Pulvérisation de mots de passe courants sur breakglass.admin (aucun MFA ne bloque l'essai)...</span>`);
      print(`<span class="out-good">Mot de passe trouvé : ${sc.sprayedPassword}</span>`);
      state.extra.sprayed = true;
      AttackGraph.reveal({ edges:['e_spray'] });
      complete('spray');
      return true;
    }

    m = cmd.match(/^connect-mguser -user (\S+) -password (\S+)$/i);
    if(m){
      const [, user, password] = m;
      const userLower = user.toLowerCase();
      if(userLower !== 'breakglass.admin' || !sc.identities[userLower]){
        print(`<span class="out-bad">Compte inconnu ou non pertinent : ${escapeHtml(user)}</span>`);
        return true;
      }
      if(!state.extra.sprayed || password !== sc.sprayedPassword){
        print(`<span class="out-bad">Authentification refusée : mot de passe incorrect.</span>`);
        return true;
      }
      state.user = 'breakglass.admin';
      updatePrompt();
      print(`<span class="out-good">Accès accordé — connecté en tant que breakglass.admin, sans le moindre challenge MFA.</span>`);
      AttackGraph.reveal({ edges:['e_owned'] });
      AttackGraph.markOwned('breakglass');
      complete('auth');
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 'breakglass.admin'){
        print(`<span class="out-info"> Coffre de secrets : kv-corp-breakglass</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else {
        print(`<span class="out-dim">(rien d'exploitable ici avec ce compte)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === 'breakglass.admin'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — chaîne complète : exclusion Conditional Access oubliée → compte de secours identifié → mot de passe jamais changé retrouvé par spray → Global Admin permanent, sans jamais passer le MFA.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : réduire le nombre de comptes de secours, les protéger par clé physique (FIDO2), et surveiller étroitement toute connexion sur ces comptes.</span>`);
        complete('flag');
        finishMission();
      } else if(file.toLowerCase() === 'flag.txt'){
        print(`<span class="out-bad">Accès refusé : ton compte (${state.user}) n'a pas les droits nécessaires sur ce coffre.</span>`);
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(file)}</span>`);
      }
      return true;
    }

    return false;
  }
};
