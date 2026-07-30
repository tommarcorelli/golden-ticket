
// ---------------------------------------------------------
// SCÉNARIO 06 — SHADOW CREDENTIALS (abus de msDS-KeyCredentialLink)
// Contrairement au scénario 03 (ACL/GenericAll), ici le droit détourné
// est étroit et discret — écrire sur UN SEUL attribut, pas tout
// contrôler — et l'exploitation ne touche jamais au mot de passe :
// aucune réinitialisation, donc aucun Event ID 4724, et l'utilisateur
// légitime continue de se connecter normalement sans rien remarquer.
// ---------------------------------------------------------
SCENARIOS.shadowcred = {
  id:'shadowcred',
  cmdBudget:8,  // Mode Budget : nombre de commandes autorisées (objectifs + marge d'exploration/erreur)
  tag:'👻 SCÉNARIO 06 · SHADOW CREDENTIALS',
  lessonTag:'📘 LEÇON · SCÉNARIO 06',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.netUserOne, NOISE.objectAcl, NOISE.whiskerAdd, NOISE.whiskerAuth],
  startUser:'m.dubois',

  identities:{
    'm.dubois':  { label:'CORP\\m.dubois', priv:'Utilisateur standard', groups:['Domain Users','IT Passwordless Rollout'], desc:'Technicien support — projet Windows Hello for Business' },
    'c.blanc':   { label:'CORP\\c.blanc', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Employée — ressources humaines' },
    's.lefevre': { label:'CORP\\s.lefevre', priv:'Administrateur du domaine', groups:['Domain Users','Domain Admins'], desc:'Direction des systèmes d\'information' }
  },

  // ACL simulées : qui a des droits inhabituels sur quel compte.
  // Ici le droit vulnérable est volontairement étroit (Write sur un
  // seul attribut), pas un contrôle total — c'est tout l'intérêt
  // pédagogique par rapport au scénario 03.
  acl:{
    's.lefevre': [
      { principal:'CORP\\Domain Admins', rights:'Full Control', normal:true },
      { principal:'CORP\\IT Passwordless Rollout', rights:'Write msDS-KeyCredentialLink', normal:false }
    ]
  },

  objectives:[
    { id:'enum',   text:'Repérer les comptes à privilèges du domaine' },
    { id:'keyacl', text:"Trouver un droit d'écriture sur l'attribut msDS-KeyCredentialLink" },
    { id:'addkey', text:"Injecter une clé d'identification (shadow credential) sur le compte cible" },
    { id:'auth',   text:"S'authentifier par cette clé (PKINIT), sans jamais toucher au mot de passe" },
    { id:'flag',   text:'Récupérer le flag' },
  ],

  hints:[
    ["Avant de chercher une faille, il faut savoir qui sont les comptes puissants de ce domaine.",
     "Liste les comptes et repère celui qui appartient au groupe Domain Admins.",
     "Commence par voir qui est qui dans le domaine : `net user /domain`"],
    ["Les droits ne sont pas toujours \"tout ou rien\" — certains ne portent que sur un seul attribut, et passent d'autant plus inaperçus.",
     "Regarde les droits accordés sur s.lefevre : un groupe dont tu es membre y figure peut-être, avec un droit très ciblé.",
     "Ton groupe CORP\\IT Passwordless Rollout a un droit d'écriture étroit sur s.lefevre. Regarde-le avec : `get-objectacl s.lefevre`"],
    ["Ce droit d'écriture porte sur un attribut précis, utilisé pour l'authentification sans mot de passe (Windows Hello for Business). Rien n'empêche d'y écrire sa propre clé.",
     "Il existe un outil pour ajouter une clé d'identification (shadow credential) sur un compte, à condition d'avoir ce droit d'écriture.",
     "Ajoute ta propre clé d'identification sur le compte cible avec : `whisker add /target:s.lefevre`"],
    ["Cette clé n'est pas un mot de passe — elle sert à s'authentifier autrement, via le même mécanisme que les certificats (PKINIT).",
     "Utilise cette clé pour t'authentifier directement en tant que s.lefevre, sans jamais connaître ni changer son mot de passe.",
     "Authentifie-toi avec la clé injectée : `whisker auth /target:s.lefevre`"],
    ["Tu es désormais Domain Admin, et le mot de passe original de s.lefevre n'a jamais changé.",
     "Regarde ce qu'il y a sur ton propre bureau, maintenant que tu es s.lefevre.",
     "Tu es maintenant Domain Admin. Regarde ton propre bureau avec `dir` puis `type flag.txt`"]
  ],

  manPages:{
    'net': { name:'net user', role:"Interroge les comptes du domaine",
      explain:"Sans argument après /domain, liste tous les comptes. Avec un nom, affiche ses détails.",
      usage:'net user /domain   |   net user <nom> /domain' },
    'get-objectacl': { name:'get-objectacl', role:"Liste les droits (ACL) accordés sur un compte",
      explain:"Un droit peut porter sur l'objet entier (GenericAll) ou sur un seul attribut précis — comme <b>msDS-KeyCredentialLink</b>, l'attribut qui stocke les clés d'authentification sans mot de passe (Windows Hello for Business, FIDO). Un droit d'écriture sur ce seul attribut suffit à s'authentifier comme le compte cible, sans jamais toucher à son mot de passe.",
      usage:'get-objectacl <nom>' },
    'whisker': { name:'whisker', role:"Manipule l'attribut msDS-KeyCredentialLink d'un compte",
      explain:"<code>add</code> injecte une nouvelle clé d'identification (shadow credential) sur le compte cible, à condition d'avoir un droit d'écriture suffisant sur cet attribut. <code>auth</code> utilise ensuite cette clé pour obtenir un ticket Kerberos (TGT) par authentification PKINIT — le même mécanisme que pour un certificat, mais sans jamais passer par une autorité de certification ni changer le mot de passe du compte.",
      usage:'whisker add /target:<nom>   |   whisker auth /target:<nom>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'net user /domain','net user ','get-objectacl ',
    'whisker add /target:','whisker auth /target:','dir','type '
  ],

  helpLine:'whoami /priv, net user /domain, net user &lt;nom&gt; /domain, get-objectacl &lt;nom&gt;, whisker add /target:&lt;nom&gt;, whisker auth /target:&lt;nom&gt;, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>net user /domain<br>net user &lt;nom&gt; /domain<br>get-objectacl &lt;nom&gt;<br>whisker add /target:&lt;nom&gt;<br>whisker auth /target:&lt;nom&gt;<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\m.dubois sur WKS-077</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🪪', title:'Authentification sans mot de passe : une nouvelle attaque de surface', html:
      `<p>Windows Hello for Business et les clés de sécurité (FIDO2) permettent de s'authentifier sans mot de passe, grâce à une paire de clés stockée dans l'attribut <b>msDS-KeyCredentialLink</b> du compte.</p>
       <p>Pour déployer ce système, les équipes IT ont souvent besoin d'un droit d'écriture sur cet attribut — un droit étroit, en apparence anodin.</p>` },
    { icon:'👻', title:'Shadow Credentials : injecter sa propre clé', html:
      `<p>Si ce droit d'écriture est mal restreint, rien n'empêche un attaquant d'y ajouter <b>sa propre clé</b> — une "shadow credential" — sur le compte d'un tiers.</p>
       <p>Cette clé permet ensuite de s'authentifier comme ce compte via PKINIT (le même mécanisme que pour un certificat), sans jamais connaître son mot de passe.</p>` },
    { icon:'🥷', title:'Pourquoi c\'est particulièrement discret', html:
      `<p>Contrairement à une réinitialisation de mot de passe, injecter une clé <b>ne modifie rien de visible</b> pour l'utilisateur légitime : il continue de se connecter normalement, et aucun Event ID 4724 (changement de mot de passe) n'est généré.</p>
       <p>Pire encore pour la défense : changer le mot de passe du compte compromis <b>ne suffit pas</b> à couper l'accès de l'attaquant — la clé injectée reste valide tant qu'elle n'est pas explicitement retirée.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>CORP\\m.dubois</b>, technicien support sur un projet d'authentification sans mot de passe. Ton groupe de projet a gardé un droit qu'il n'aurait plus dû avoir.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Domain Admin obtenu',
  completeSub:"Une clé injectée, jamais un mot de passe touché.",
  chainSteps:[
    {icon:'🔎', label:'Recon'}, {icon:'🪪', label:'Droit trouvé'},
    {icon:'👻', label:'Clé injectée'}, {icon:'👑', label:'Domain Admin'}
  ],
  flag:'FLAG{shadow_credentials_msdskeycredentiallink_pkinit}',

  graph:{
    nodes:[
      { id:'m.dubois', label:'m.dubois', type:'user' },
      { id:'c.blanc', label:'c.blanc', type:'user' },
      { id:'s.lefevre', label:'s.lefevre', type:'admin' },
      { id:'grp_passwordless', label:'IT Passwordless Rollout', type:'group' }
    ],
    edges:[
      { id:'e_member', from:'m.dubois', to:'grp_passwordless', type:'memberof', label:'MemberOf' },
      { id:'e_acl', from:'grp_passwordless', to:'s.lefevre', type:'abuse', label:'Write msDS-KeyCredentialLink (oublié)' },
      { id:'e_owned', from:'m.dubois', to:'s.lefevre', type:'owned', label:'Shadow credential + PKINIT' }
    ]
  },

  deepDive:{
    mitre:[{id:'T1098', name:"Account Manipulation"}],
    why:"L'attribut msDS-KeyCredentialLink stocke les clés utilisées pour l'authentification sans mot de passe (Windows Hello for Business, FIDO2). Un droit d'écriture sur ce seul attribut — souvent accordé largement pendant un déploiement, puis jamais retiré — permet à quiconque le possède d'y ajouter sa propre clé, et de s'authentifier comme le compte cible via PKINIT. C'est un droit étroit, donc facile à accorder sans réfléchir, et facile à oublier dans un audit qui ne cherche que les GenericAll évidents.",
    defenses:[
      "Auditer spécifiquement les droits d'écriture sur msDS-KeyCredentialLink, pas seulement les droits larges comme GenericAll",
      "Limiter au strict nécessaire, et dans le temps, les groupes impliqués dans un déploiement d'authentification sans mot de passe",
      "Surveiller les modifications de l'attribut msDS-KeyCredentialLink (Event ID 5136) en dehors des postes et comptes attendus",
      "Retenir qu'une réinitialisation de mot de passe seule ne suffit pas à révoquer l'accès : il faut aussi supprimer toute clé injectée sur le compte"
    ],
    quiz:[
      { q:"Pourquoi un droit d'écriture sur msDS-KeyCredentialLink est-il souvent oublié lors d'un audit d'ACL ?",
        options:["Il n'existe dans aucun journal Windows","C'est un droit étroit sur un seul attribut, moins visible qu'un droit large comme GenericAll","Il ne peut être accordé qu'aux comptes de service","Microsoft ne documente pas cet attribut"],
        correct:1,
        explain:"Un audit qui cherche surtout les droits larges et évidents (GenericAll, Full Control) peut facilement laisser passer un droit d'écriture étroit sur un seul attribut, techniquement tout aussi dangereux ici." },
      { q:"Pourquoi cette technique ne génère-t-elle pas d'Event ID 4724 (changement de mot de passe) ?",
        options:["Parce que l'Event ID 4724 est désactivé par défaut","Parce qu'aucun mot de passe n'est jamais modifié — seule une clé est ajoutée en plus","Parce que l'attaquant supprime le journal après coup","Parce que 4724 ne concerne que les comptes de service"],
        correct:1,
        explain:"La technique n'a jamais besoin de toucher au mot de passe du compte : elle ajoute simplement une clé d'authentification alternative, ce qui ne déclenche pas les mêmes événements qu'une réinitialisation." },
      { q:"Pourquoi changer le mot de passe du compte compromis ne suffit-il pas à couper l'accès de l'attaquant ?",
        options:["Le mot de passe et la clé injectée sont deux méthodes d'authentification indépendantes — la clé reste valide tant qu'elle n'est pas retirée explicitement","Changer un mot de passe ne fonctionne jamais sur les comptes Domain Admin","La clé injectée devient automatiquement le nouveau mot de passe","Il faut redémarrer le contrôleur de domaine pour que le changement prenne effet"],
        correct:0,
        explain:"PKINIT via la clé injectée est un chemin d'authentification totalement séparé du mot de passe. Sans supprimer explicitement la clé de msDS-KeyCredentialLink, l'attaquant garde son accès même après un changement de mot de passe." }
    ]
  },

  initState(){ return { shadowKeyTarget:null }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.shadowcred;

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
          print(`<span class="out-warn">  ${e.principal} — ${e.rights}  ⚠ droit étroit mais suffisant pour s'authentifier</span>`);
        }
      });
      if(entries.some(e => !e.normal)){
        AttackGraph.reveal({ edges:['e_member','e_acl'] });
        complete('keyacl');
      }
      return true;
    }

    m = lower.match(/^whisker add \/target:(\S+)$/);
    if(m){
      const name = m[1];
      const entries = sc.acl[name] || [];
      const me = sc.identities[state.user];
      const hasRight = entries.some(e => !e.normal && me.groups.some(g => e.principal.toLowerCase().endsWith(g.toLowerCase())));
      if(!hasRight){
        print(`<span class="out-bad">Accès refusé : tu n'as pas de droit d'écriture sur msDS-KeyCredentialLink pour ce compte.</span>`);
        return true;
      }
      print(`<span class="out-good">Clé d'identification injectée avec succès sur ${name} (msDS-KeyCredentialLink).</span>`);
      print(`<span class="out-dim">💡 Empreinte de la clé : 1a3f9c...(tronquée). Aucun mot de passe modifié — l'utilisateur légitime peut continuer à se connecter normalement, sans rien remarquer.</span>`);
      state.extra.shadowKeyTarget = name;
      AttackGraph.reveal({ edges:['e_acl'] });
      complete('addkey');
      return true;
    }

    m = lower.match(/^whisker auth \/target:(\S+)$/);
    if(m){
      const name = m[1];
      if(!sc.identities[name]){ print(`<span class="out-bad">Compte introuvable.</span>`); return true; }
      if(state.extra.shadowKeyTarget !== name){
        print(`<span class="out-bad">Aucune clé d'identification injectée pour ce compte.</span>`);
        return true;
      }
      state.user = name;
      updatePrompt();
      print(`<span class="out-good">TGT Kerberos obtenu par PKINIT avec la clé injectée — session ouverte en tant que ${sc.identities[name].label}.</span>`);
      print(`<span class="out-dim">💡 Le mot de passe original de ce compte n'a jamais été consulté ni modifié.</span>`);
      AttackGraph.reveal({ edges:['e_owned'] });
      AttackGraph.markOwned(name);
      complete('auth');
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 's.lefevre'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\s.lefevre\\Desktop</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
      } else {
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  (rien d'intéressant ici)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === 's.lefevre'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — chaîne complète : droit d'écriture étroit oublié (msDS-KeyCredentialLink) → clé injectée → authentification PKINIT → Domain Admin.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : auditer spécifiquement les droits sur msDS-KeyCredentialLink, pas seulement les GenericAll évidents — et retenir qu'un changement de mot de passe seul ne révoque pas une clé injectée.</span>`);
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
