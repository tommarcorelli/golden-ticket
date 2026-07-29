
// ---------------------------------------------------------
// SCÉNARIO 05 — ABUS DE CERTIFICATS (ADCS / ESC1)
// ---------------------------------------------------------
SCENARIOS.adcs = {
  id:'adcs',
  cmdBudget:8,  // Mode Budget : nombre de commandes autorisées (objectifs + marge d'exploration/erreur)
  tag:'📜 SCÉNARIO 05 · CERTIFICATS (ADCS ESC1)',
  lessonTag:'📘 LEÇON · SCÉNARIO 05',
  opsecEnabled:true,
  noiseRules:[NOISE.certipyFind, NOISE.certipyReq, NOISE.certipyAuth],
  startUser:'j.rossi',

  identities:{
    'j.rossi':       { label:'CORP\\j.rossi', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Employé — support niveau 1' },
    'administrator': { label:'CORP\\administrator', priv:'Administrateur intégré', groups:['Domain Users','Domain Admins'], desc:'Compte administrateur intégré du domaine' }
  },

  // Modèles de certificats publiés par l'autorité de certification (CA) du domaine.
  templates:{
    'User': {
      enroll:'Domain Users',
      esc1:false,
      flags:'—',
      desc:"Modèle standard fourni par défaut. N'importe qui peut s'enrôler, mais le sujet du certificat est toujours forcé à l'identité du demandeur : impossible de usurper quelqu'un d'autre."
    },
    'SecureLogin': {
      enroll:'Domain Admins',
      esc1:false,
      flags:'—',
      desc:"Modèle réservé à l'authentification forte des administrateurs. Solide sur le papier — mais seuls les Domain Admins peuvent s'y enrôler, donc inutile pour élever ses privilèges."
    },
    'WebServer': {
      enroll:'Domain Users',
      esc1:true,
      flags:'ENROLLEE_SUPPLIES_SUBJECT',
      desc:"Modèle publié à l'origine pour l'authentification de serveurs web par certificat. Ouvert à tous les utilisateurs du domaine, ET le drapeau ENROLLEE_SUPPLIES_SUBJECT laisse le DEMANDEUR choisir librement l'identité (SAN) inscrite dans le certificat."
    }
  },

  objectives:[
    { id:'enum',   text:'Lister les modèles de certificats publiés par la CA' },
    { id:'find',   text:'Repérer le modèle vulnérable (ENROLLEE_SUPPLIES_SUBJECT)' },
    { id:'forge',  text:"Demander un certificat en usurpant l'identité de l'administrateur" },
    { id:'auth',   text:'Authentification via ce certificat (PKINIT)' },
    { id:'flag',   text:'Récupérer le flag' },
  ],

  hints:[
    ["Avant de savoir quel modèle exploiter, il faut d'abord voir ce que la CA du domaine propose.",
     "Il existe une commande pour interroger l'autorité de certification et lister ses modèles publiés, avec qui peut s'y enrôler.",
     "Commence par : `certipy find` — elle liste les modèles, qui peut s'y enrôler, et leurs drapeaux."],
    ["Un modèle réservé aux administrateurs ne t'aide à rien : tu ne peux même pas t'y enrôler. Cherche plutôt un modèle ouvert à tout le monde MAIS avec un drapeau qui ne devrait pas être là.",
     "Le drapeau à repérer s'appelle ENROLLEE_SUPPLIES_SUBJECT — il veut dire que c'est TOI, le demandeur, qui choisis l'identité écrite dans le certificat, pas la CA.",
     "Le modèle 'WebServer' est ouvert à Domain Users ET porte le drapeau ENROLLEE_SUPPLIES_SUBJECT — c'est ta cible (c'est la faille bien connue sous le nom d'ESC1)."],
    ["Puisque tu peux choisir l'identité du certificat toi-même, demandes-en un pour quelqu'un de bien plus puissant que toi.",
     "Il existe une commande pour demander (request) un certificat sur un modèle donné, en précisant l'UPN (identité) que tu veux voir apparaître dedans.",
     "Demande un certificat sur le modèle vulnérable en te faisant passer pour l'administrateur : `certipy req -template WebServer -upn administrator@corp.local`"],
    ["Un certificat valide pour une identité permet de s'authentifier auprès du domaine sans jamais connaître le mot de passe — via Kerberos PKINIT.",
     "Il existe une commande pour t'authentifier directement avec le certificat obtenu.",
     "Authentifie-toi avec ce certificat : `certipy auth -cert administrator.pfx` — tu obtiens une session en tant qu'administrator."],
    ["Une fois connecté avec les droits Domain Admin, la suite est toujours la même.",
     "Regarde ce qu'il y a sur ce bureau.",
     "`dir` puis `type flag.txt` une fois que tu es administrator."]
  ],

  manPages:{
    'certipy': { name:'certipy find', role:"Interroge l'autorité de certification (CA) du domaine",
      explain:"Liste les modèles de certificats publiés, qui peut s'y enrôler, et leurs drapeaux de configuration. Un modèle mal configuré peut permettre bien plus que prévu — jusqu'à usurper n'importe quelle identité (drapeau ENROLLEE_SUPPLIES_SUBJECT, faille connue sous le nom d'ESC1).",
      usage:'certipy find' },
    'certipy-req': { name:'certipy req', role:'Demande un certificat sur un modèle donné',
      explain:"Envoie une demande d'enrôlement à la CA pour le modèle choisi. Si ce modèle autorise le demandeur à fournir lui-même le sujet du certificat (ENROLLEE_SUPPLIES_SUBJECT), l'UPN précisé peut être celui de n'importe quel compte — y compris un administrateur.",
      usage:'certipy req -template <nom> -upn <identité>' },
    'certipy-auth': { name:'certipy auth', role:'Authentification via un certificat (PKINIT)',
      explain:"Utilise un certificat valide pour obtenir un ticket Kerberos (TGT) au nom de l'identité inscrite dedans — sans jamais connaître le mot de passe du compte visé.",
      usage:'certipy auth -cert <fichier.pfx>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'certipy find','certipy req -template ','certipy auth -cert ','dir','type '
  ],

  helpLine:'whoami /priv, certipy find, certipy req -template &lt;nom&gt; -upn &lt;identité&gt;, certipy auth -cert &lt;fichier.pfx&gt;, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>certipy find<br>certipy req -template &lt;nom&gt; -upn &lt;identité&gt;<br>certipy auth -cert &lt;fichier.pfx&gt;<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\j.rossi sur WKS-204</span>`,
    `<span class="out-info">Une autorité de certification (AD CS) a été déployée récemment pour l'authentification par carte à puce.</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'📜', title:'AD CS : des certificats comme identité', html:
      `<p><b>Active Directory Certificate Services</b> (AD CS) permet à une entreprise de faire tourner sa propre autorité de certification (CA) interne — pour signer des sites web internes, mais aussi pour <b>authentifier des comptes</b> via un certificat plutôt qu'un mot de passe.</p>
       <p>Un certificat valide pour une identité permet de s'authentifier au domaine sans jamais connaître le mot de passe, via Kerberos <b>PKINIT</b>.</p>` },
    { icon:'🧩', title:'Les modèles de certificats (templates)', html:
      `<p>La CA publie des <b>modèles</b> qui définissent : qui a le droit de demander (s'enrôler) un certificat sur ce modèle, et quelles informations d'identité ce certificat contiendra.</p>
       <p>Normalement, la CA impose que le certificat porte l'identité du demandeur — pas celle de quelqu'un d'autre.</p>` },
    { icon:'🚩', title:"L'ESC1 : quand le demandeur choisit son identité", html:
      `<p>Certains modèles portent un drapeau <b>ENROLLEE_SUPPLIES_SUBJECT</b> : c'est le <b>demandeur</b>, pas la CA, qui choisit l'identité (SAN) écrite dans le certificat.</p>
       <p>Si ce modèle est en plus ouvert à n'importe quel utilisateur authentifié, n'importe qui peut demander — et obtenir — un certificat valide pour l'<b>administrateur du domaine</b>. C'est la faille la plus connue d'AD CS, nommée <b>ESC1</b>.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>CORP\\j.rossi</b>, employé standard. Une autorité de certification vient d'être déployée. Quelque part parmi ses modèles publiés, une configuration bien trop permissive t'attend.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Domain Admin obtenu',
  completeSub:'Un modèle de certificat trop permissif, une identité usurpée.',
  chainSteps:[
    {icon:'🔎', label:'Recon CA'}, {icon:'🚩', label:'Modèle ESC1'},
    {icon:'📜', label:'Certificat forgé'}, {icon:'🔑', label:'PKINIT'}, {icon:'👑', label:'Domain Admin'}
  ],
  flag:'FLAG{adcs_esc1_enrollee_supplies_subject}',

  graph:{
    nodes:[
      { id:'j.rossi', label:'j.rossi', type:'user' },
      { id:'tpl_user', label:'Modèle: User', type:'service' },
      { id:'tpl_securelogin', label:'Modèle: SecureLogin', type:'service' },
      { id:'tpl_webserver', label:'Modèle: WebServer', type:'service' },
      { id:'administrator', label:'administrator', type:'admin' }
    ],
    edges:[
      { id:'e_enroll', from:'j.rossi', to:'tpl_webserver', type:'abuse', label:'Enrollment Rights + ESC1' },
      { id:'e_forge', from:'tpl_webserver', to:'administrator', type:'auth', label:'Certificat forgé (SAN)' },
      { id:'e_owned', from:'j.rossi', to:'administrator', type:'owned', label:'PKINIT réussi' }
    ]
  },

  deepDive:{
    mitre:[{id:'T1649', name:"Steal or Forge Authentication Certificates"}],
    why:"AD CS est souvent déployé rapidement, avec les modèles fournis par défaut ou copiés d'un ancien modèle sans revoir les droits d'enrôlement ni les drapeaux hérités. Le drapeau ENROLLEE_SUPPLIES_SUBJECT, en particulier, est resté sur d'anciens modèles conçus avant que ce risque ne soit largement documenté (recherche publiée par SpecterOps en 2021, ESC1 à ESC8+).",
    defenses:[
      "Auditer tous les modèles de certificats publiés : qui peut s'enrôler, et quels drapeaux sont actifs (en particulier ENROLLEE_SUPPLIES_SUBJECT)",
      "Restreindre les droits d'enrôlement aux seuls comptes qui en ont réellement besoin, pas à Domain Users par défaut",
      "Activer StrongCertificateBindingEnforcement et le mappage strict certificat ↔ compte",
      "Surveiller les événements d'émission de certificats (4886/4887) et les authentifications PKINIT inhabituelles pour des comptes à privilèges"
    ],
    quiz:[
      { q:"Que permet concrètement le drapeau ENROLLEE_SUPPLIES_SUBJECT sur un modèle de certificat ?",
        options:["Le demandeur choisit lui-même l'identité (le sujet) inscrite dans le certificat","Le certificat expire automatiquement après usage","Seul un administrateur peut demander ce certificat","Le certificat ne fonctionne que sur la machine qui l'a demandé"],
        correct:0,
        explain:"Ce drapeau laisse le demandeur préciser le sujet du certificat — s'il est ouvert à tous, n'importe qui peut demander un certificat au nom de l'administrateur." },
      { q:"Comment ce certificat forgé permet-il ensuite de s'authentifier comme l'administrateur ?",
        options:["Par PKINIT, l'authentification Kerberos par certificat","En le collant dans un fichier de mots de passe","En le renommant avec le nom de l'administrateur","Il ne permet pas de s'authentifier, seulement de le visualiser"],
        correct:0,
        explain:"PKINIT est l'extension Kerberos qui permet de s'authentifier avec un certificat plutôt qu'un mot de passe — un certificat au nom de l'admin y suffit." },
      { q:"Quelle pratique aurait empêché ce scénario dès le départ ?",
        options:["Auditer les modèles publiés et restreindre les droits d'enrôlement","Changer le mot de passe de l'administrateur plus souvent","Désactiver Kerberos au profit de NTLM","Chiffrer le contrôleur de domaine avec BitLocker"],
        correct:0,
        explain:"Un audit régulier des modèles de certificats publiés (droits d'enrôlement, drapeaux hérités) aurait révélé le modèle vulnérable avant qu'un attaquant ne l'exploite." }
    ]
  },

  initState(){ return { cert:null }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.adcs;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'certipy find'){
      print(`<span class="out-info">Modèles de certificats publiés par CORP-CA :</span>`);
      Object.keys(sc.templates).forEach(name => {
        const t = sc.templates[name];
        print(`<span class="out-dim">  ${name} — Enrollment Rights: ${t.enroll} — Drapeaux: ${t.flags}</span>`);
      });
      print(`<span class="out-warn">⚠ Un des modèles laisse le demandeur choisir lui-même l'identité du certificat (ENROLLEE_SUPPLIES_SUBJECT). Regarde bien qui peut s'y enrôler.</span>`);
      AttackGraph.reveal({ nodes:['j.rossi','tpl_user','tpl_securelogin','tpl_webserver'] });
      complete('enum');
      return true;
    }

    m = lower.match(/^certipy req -template (\S+) -upn (\S+)$/);
    if(m){
      const tplName = Object.keys(sc.templates).find(n => n.toLowerCase() === m[1]);
      const upn = m[2];
      if(!tplName){ print(`<span class="out-bad">Modèle introuvable : ${escapeHtml(m[1])}</span>`); return true; }
      const t = sc.templates[tplName];
      if(t.enroll === 'Domain Admins'){
        print(`<span class="out-bad">Accès refusé : ce modèle n'autorise l'enrôlement qu'aux membres de Domain Admins.</span>`);
        return true;
      }
      complete('find');
      const targetUser = upn.split('@')[0].toLowerCase();
      if(!t.esc1){
        if(targetUser === state.user.toLowerCase()){
          print(`<span class="out-good">Certificat émis pour ${upn} — mais c'est ta propre identité, ça ne t'avance à rien.</span>`);
        } else {
          print(`<span class="out-bad">Demande refusée : ce modèle force le sujet du certificat à l'identité du demandeur (pas de ENROLLEE_SUPPLIES_SUBJECT). Impossible de spécifier ${upn}.</span>`);
        }
        return true;
      }
      print(`<span class="out-good">Certificat émis avec succès pour l'identité ${upn} (modèle ${tplName}, ENROLLEE_SUPPLIES_SUBJECT).</span>`);
      print(`<span class="out-dim">Fichier : ${targetUser}.pfx</span>`);
      state.extra.cert = targetUser;
      AttackGraph.reveal({ edges:['e_enroll','e_forge'] });
      complete('forge');
      return true;
    }

    m = lower.match(/^certipy auth -cert (\S+)$/);
    if(m){
      const certFile = m[1].replace(/\.pfx$/,'');
      if(!state.extra.cert || state.extra.cert !== certFile){
        print(`<span class="out-bad">Certificat introuvable ou invalide : ${escapeHtml(m[1])}</span>`);
        return true;
      }
      if(!sc.identities[certFile]){
        print(`<span class="out-bad">Identité inconnue pour ce certificat.</span>`);
        return true;
      }
      print(`<span class="out-good">Authentification PKINIT réussie — TGT obtenu pour ${sc.identities[certFile].label}.</span>`);
      state.user = certFile;
      updatePrompt();
      AttackGraph.reveal({ edges:['e_owned'] });
      AttackGraph.markOwned(certFile);
      complete('auth');
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 'administrator'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\administrator\\Desktop</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else {
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  (rien d'intéressant ici)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === 'administrator'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — chaîne complète : modèle de certificat vulnérable (ESC1) → certificat usurpé → authentification PKINIT → Domain Admin.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : auditer tous les modèles de certificats publiés, restreindre les droits d'enrôlement, désactiver ENROLLEE_SUPPLIES_SUBJECT quand il n'est pas nécessaire.</span>`);
        complete('flag');
        finishMission();
      } else if(file.toLowerCase() === 'flag.txt'){
        print(`<span class="out-bad">Accès refusé : tu n'as pas les droits de lecture sur ce fichier.</span>`);
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(file)}</span>`);
      }
      return true;
    }

    return false;
  }
};
