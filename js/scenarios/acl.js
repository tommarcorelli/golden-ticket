
// ---------------------------------------------------------
// SCÉNARIO 03 — ABUS D'ACL (GenericAll)
// ---------------------------------------------------------
SCENARIOS.acl = {
  id:'acl',
  tag:'👑 SCÉNARIO 03 · ABUS D\'ACL',
  lessonTag:'📘 LEÇON · SCÉNARIO 03',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.netUserOne, NOISE.objectAcl, NOISE.resetPassword, NOISE.runas],
  startUser:'j.dupont',

  identities:{
    'j.dupont':  { label:'CORP\\j.dupont', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Employé — support niveau 1' },
    'r.simon':   { label:'CORP\\r.simon', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Employé — marketing' },
    'h.morel':   { label:'CORP\\h.morel', priv:'Administrateur du domaine', groups:['Domain Users','Domain Admins'], desc:'Support IT senior' },
    'administrator': { label:'CORP\\administrator', priv:'Administrateur intégré', groups:['Domain Users','Domain Admins'], desc:'Compte administrateur intégré du domaine' }
  },

  // ACL simulées : qui a des droits inhabituels sur quel compte
  acl:{
    'h.morel': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true },
      { principal:'CORP\\j.dupont', rights:'GenericAll', normal:false }
    ],
    'r.simon': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true }
    ],
    'administrator': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true }
    ]
  },

  objectives:[
    { id:'enum',   text:'Repérer les comptes à privilèges du domaine' },
    { id:'acl',    text:'Trouver une ACL mal configurée (GenericAll)' },
    { id:'reset',  text:'Réinitialiser le mot de passe grâce à cette permission' },
    { id:'access', text:'Ouvrir une session avec le compte compromis' },
    { id:'flag',   text:'Récupérer le flag' },
  ],

  hints:[
    ["Avant de chercher une faille, il faut savoir qui sont les comptes puissants de ce domaine.",
     "Liste les comptes et repère celui qui appartient au groupe Domain Admins.",
     "Commence par voir qui est qui dans le domaine : `net user /domain`"],
    ["Les permissions sur un compte ne sont pas toujours celles qu'on croit — quelqu'un a peut-être oublié d'en retirer une.",
     "Il existe une commande pour lister les droits accordés sur un compte cible. Essaie-la sur h.morel.",
     "h.morel a l'air intéressant (Domain Admin). Regarde qui a des droits sur son compte : `get-objectacl h.morel`"],
    ["Un droit très puissant, mal placé, permet de littéralement tout changer sur le compte visé — y compris son secret d'authentification.",
     "Ce droit s'appelle GenericAll. Utilise-le pour définir un nouveau mot de passe sur le compte Domain Admin.",
     "Un compte qui ne devrait pas avoir de droits ici en a pourtant (GenericAll). Ce droit permet de tout changer sur le compte cible — y compris son mot de passe : `set-domainuserpassword -identity h.morel -newpassword <ton_choix>`"],
    ["Tu connais maintenant un mot de passe valide pour ce compte.",
     "Il existe une commande Windows pour ouvrir une session avec cette identité.",
     "Une fois le mot de passe réinitialisé, connecte-toi : `runas /user:h.morel cmd`"],
    ["Tu es désormais Domain Admin.",
     "Regarde ce qu'il y a sur ton propre bureau, maintenant que tu es h.morel.",
     "Tu es maintenant Domain Admin. Regarde ton propre bureau avec `dir` puis `type flag.txt`"]
  ],

  manPages:{
    'net': { name:'net user', role:"Interroge les comptes du domaine",
      explain:"Sans argument après /domain, liste tous les comptes. Avec un nom, affiche ses détails.",
      usage:'net user /domain   |   net user <nom> /domain' },
    'get-objectacl': { name:'get-objectacl', role:"Liste les droits (ACL) accordés sur un compte",
      explain:"Chaque objet AD a une liste de contrôle d'accès (ACL/DACL) qui dit qui peut faire quoi dessus. Un droit <b>GenericAll</b> équivaut à un contrôle total de l'objet — y compris changer son mot de passe — même sans être administrateur du domaine. Ces droits sont parfois accordés temporairement (dépannage, délégation) puis jamais retirés.",
      usage:'get-objectacl <nom>' },
    'set-domainuserpassword': { name:'set-domainuserpassword', role:"Réinitialise le mot de passe d'un compte cible",
      explain:"Nécessite un droit suffisant sur le compte cible (GenericAll, WriteDACL, ou le droit dédié 'Reset Password'). Contrairement au Kerberoasting, ceci ne casse rien : le nouveau mot de passe est choisi directement, sans jamais connaître l'ancien.",
      usage:'set-domainuserpassword -identity <nom> -newpassword <valeur>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'net user /domain','net user ','get-objectacl ',
    'set-domainuserpassword -identity ','runas /user:','dir','type '
  ],

  helpLine:'whoami /priv, net user /domain, net user &lt;nom&gt; /domain, get-objectacl &lt;nom&gt;, set-domainuserpassword -identity &lt;nom&gt; -newpassword &lt;valeur&gt;, runas /user:&lt;nom&gt; cmd, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>net user /domain<br>net user &lt;nom&gt; /domain<br>get-objectacl &lt;nom&gt;<br>set-domainuserpassword -identity &lt;nom&gt; -newpassword &lt;valeur&gt;<br>runas /user:&lt;nom&gt; cmd<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\j.dupont sur WKS-018</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🗂️', title:'ACL & DACL : qui a le droit de faire quoi', html:
      `<p>Chaque objet Active Directory (compte, groupe, machine...) a une <b>liste de contrôle d'accès</b> (ACL) qui définit précisément qui peut le lire, le modifier, ou le supprimer.</p>
       <p>Ces droits peuvent être accordés très finement — pas seulement "admin ou pas admin".</p>` },
    { icon:'🔑', title:'Le droit GenericAll', html:
      `<p><b>GenericAll</b> est l'un des droits les plus puissants qui existent sur un objet AD : il équivaut à un contrôle total, y compris le droit de <b>changer le mot de passe</b> du compte ciblé.</p>
       <p>Un compte avec GenericAll sur un Domain Admin n'a même pas besoin d'être administrateur lui-même pour en devenir un.</p>` },
    { icon:'🩹', title:"L'erreur classique : le droit oublié", html:
      `<p>Ces droits sont souvent accordés <b>temporairement</b> — un dépannage, une délégation ponctuelle — puis jamais retirés. Avec le temps, un domaine accumule des permissions qui n'ont plus aucune raison d'exister.</p>
       <p>Un attaquant qui énumère patiemment ces ACL peut trouver un chemin vers Domain Admin qui ne passe par aucune faille technique — juste par une permission oubliée.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>CORP\\j.dupont</b>, employé standard. Quelque part dans ce domaine, une permission mal configurée te donne bien plus de pouvoir que ton statut ne le laisse penser.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Domain Admin obtenu',
  completeSub:'Permission oubliée, contrôle total du domaine.',
  chainSteps:[
    {icon:'🔎', label:'Recon'}, {icon:'🗂️', label:'ACL trouvée'},
    {icon:'🔑', label:'Reset mdp'}, {icon:'👑', label:'Domain Admin'}
  ],
  flag:'FLAG{genericall_acl_abuse_domain_admin}',

  graph:{
    nodes:[
      { id:'j.dupont', label:'j.dupont', type:'user' },
      { id:'r.simon', label:'r.simon', type:'user' },
      { id:'h.morel', label:'h.morel', type:'admin' },
      { id:'administrator', label:'administrator', type:'admin' }
    ],
    edges:[
      { id:'e_acl', from:'j.dupont', to:'h.morel', type:'abuse', label:'GenericAll (oublié)' },
      { id:'e_owned', from:'j.dupont', to:'h.morel', type:'owned', label:'Reset + accès' }
    ]
  },

  deepDive:{
    mitre:[{id:'T1098', name:"Account Manipulation"}],
    why:"Les ACL Active Directory permettent une délégation très fine des droits — utile, mais dangereuse si elle n'est jamais auditée. Une permission accordée pour une tâche ponctuelle (dépannage, script d'automatisation, prestataire externe) reste active tant que personne ne la retire explicitement, parfois pendant des années.",
    defenses:[
      "Auditer régulièrement les ACL des comptes et groupes sensibles (BloodHound côté défense, ou équivalent)",
      "Appliquer le principe du moindre privilège : accorder des droits temporaires avec expiration automatique",
      "Surveiller les modifications d'ACL sur les objets à privilège (Event ID 5136)",
      "Isoler les comptes à haut privilège dans un modèle de tiering (Tier 0 / 1 / 2)"
    ],
    quiz:[
      { q:"Pourquoi une ACL dangereuse reste-t-elle souvent en place pendant des années ?",
        options:["Windows la supprime automatiquement après 90 jours","Elle reste active tant que personne ne la retire explicitement","Elle n'est visible que par l'administrateur qui l'a créée","Les ACL AD expirent seulement en cas de changement de mot de passe"],
        correct:1,
        explain:"Une permission accordée pour un besoin ponctuel n'a pas de date d'expiration native : sans audit régulier, elle survit largement au-delà de son utilité." },
      { q:"Quel outil est couramment utilisé côté défense pour auditer les chemins d'abus d'ACL avant qu'un attaquant ne les trouve ?",
        options:["BloodHound","Wireshark","Nmap","Metasploit"],
        correct:0,
        explain:"BloodHound cartographie les relations AD (groupes, ACL, sessions) et révèle les chemins d'escalade de privilèges — le même outil sert aussi à l'attaque, d'où son usage défensif préventif." },
      { q:"Quel principe limite le risque qu'une ACL trop permissive mène jusqu'à Domain Admin ?",
        options:["Le moindre privilège avec droits temporaires","Le partage de mots de passe entre administrateurs","La désactivation complète des ACL","L'authentification unique (SSO) généralisée"],
        correct:0,
        explain:"Accorder des droits temporaires, avec expiration automatique et strictement nécessaires à la tâche, réduit la fenêtre et la portée d'une ACL mal configurée." }
    ]
  },

  initState(){ return { newPassword:null }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.acl;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'net user /domain'){
      print(`<span class="out-info">Comptes du domaine CORP.LOCAL :</span>`);
      Object.keys(sc.identities).forEach(name => print(`<span class="out-dim">  ${name}</span>`));
      AttackGraph.reveal({ nodes:Object.keys(sc.identities) });
      complete('enum');
      return true;
    }

    m = lower.match(/^net user (\S+) \/domain$/);
    if(m){
      const name = m[1];
      const u = sc.identities[name];
      if(!u){ print(`<span class="out-bad">Utilisateur introuvable : ${name}</span>`); return true; }
      print(`<span class="out-info">Nom du compte : ${name}</span>`);
      print(`<span class="out-info">Description : ${u.desc}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      if(u.groups.includes('Domain Admins')){
        print(`<span class="out-warn">⚠ Ce compte est administrateur du domaine — une cible de choix.</span>`);
      }
      complete('enum');
      return true;
    }

    m = lower.match(/^get-objectacl (\S+)$/);
    if(m){
      const name = m[1];
      const entries = sc.acl[name];
      if(!entries){ print(`<span class="out-bad">Objet introuvable : ${escapeHtml(name)}</span>`); return true; }
      print(`<span class="out-info">ACL sur le compte ${name} :</span>`);
      entries.forEach(e => {
        if(e.normal){
          print(`<span class="out-dim">  ${e.principal} — ${e.rights}</span>`);
        } else {
          print(`<span class="out-warn">  ${e.principal} — ${e.rights}  ⚠ inhabituel pour ce compte</span>`);
        }
      });
      if(entries.some(e => !e.normal)){
        AttackGraph.reveal({ edges:['e_acl'] });
        complete('acl');
      }
      return true;
    }

    m = lower.match(/^set-domainuserpassword -identity (\S+) -newpassword (\S+)$/);
    if(m){
      const [, name, pwd] = m;
      const entries = sc.acl[name] || [];
      const hasRight = entries.some(e => !e.normal && e.principal.toLowerCase().endsWith(state.user.toLowerCase()));
      if(!hasRight){
        print(`<span class="out-bad">Accès refusé : tu n'as pas les droits nécessaires sur ce compte.</span>`);
        return true;
      }
      print(`<span class="out-good">Mot de passe de ${name} réinitialisé avec succès.</span>`);
      print(`<span class="out-dim">💡 Aucune alerte de type "mot de passe cassé" ici — c'est une réinitialisation légitime, silencieuse.</span>`);
      state.extra.newPassword = pwd;
      state.extra.resetTarget = name;
      AttackGraph.reveal({ tags:{ [name]:'reset' } });
      complete('reset');
      return true;
    }

    m = lower.match(/^runas \/user:(\S+) cmd$/);
    if(m){
      const name = m[1];
      if(!sc.identities[name]){ print(`<span class="out-bad">Compte introuvable.</span>`); return true; }
      if(state.extra.resetTarget !== name || !state.extra.newPassword){
        print(`<span class="out-bad">Mot de passe inconnu pour ce compte.</span>`);
        return true;
      }
      state.user = name;
      updatePrompt();
      print(`<span class="out-good">Nouvelle session ouverte en tant que ${sc.identities[name].label}</span>`);
      AttackGraph.reveal({ edges:['e_owned'] });
      AttackGraph.markOwned(name);
      complete('access');
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 'h.morel'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\h.morel\\Desktop</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else {
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  (rien d'intéressant ici)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === 'h.morel'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — chaîne complète : énumération → ACL mal configurée (GenericAll) → réinitialisation → Domain Admin.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : auditer régulièrement les ACL des comptes sensibles (BloodHound côté défense), retirer les permissions temporaires oubliées.</span>`);
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
