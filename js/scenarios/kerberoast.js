SCENARIOS.kerberoast = {
  id:'kerberoast',
  cmdBudget:9,  // Mode Budget : nombre de commandes autorisées (objectifs + marge d'exploration/erreur)
  tag:'🎫 SCÉNARIO 01 · KERBEROASTING',
  lessonTag:'📘 LEÇON · SCÉNARIO 01',
  opsecEnabled:true,
  noiseRules:[NOISE.netUserAll, NOISE.netUserOne, NOISE.domainUserSpn, NOISE.kerberoast, NOISE.runas],
  startUser:'j.dupont',

  identities:{
    'j.dupont':    { label:'CORP\\j.dupont', priv:'Utilisateur standard', groups:['Domain Users'], desc:'Employé — comptabilité' },
    'a.martin':    { label:'CORP\\a.martin', priv:'Administrateur IT', groups:['Domain Users','Domain Admins'], desc:'Administrateur du domaine' },
    'svc_backup':  { label:'CORP\\svc_backup', priv:'Compte de service', groups:['Domain Users','Backup Operators'],
                     desc:'Compte de service — sauvegardes nocturnes',
                     spn:'MSSQLSvc/sql01.corp.local:1433',
                     hash:'$krb5tgs$23$*svc_backup$CORP.LOCAL*$9f8c...(ticket TGS tronqué)',
                     crackedPassword:'Summer2024!' },
    'administrator': { label:'CORP\\administrator', priv:'Administrateur intégré', groups:['Domain Users','Domain Admins'], desc:'Compte administrateur intégré du domaine' }
  },

  objectives:[
    { id:'enum',       text:'Énumérer les comptes du domaine' },
    { id:'spn',        text:'Trouver le compte de service avec un SPN' },
    { id:'kerberoast', text:'Extraire le ticket Kerberos du compte' },
    { id:'crack',      text:'Cracker le mot de passe du ticket' },
    { id:'access',     text:'Ouvrir une session avec ce compte' },
    { id:'flag',       text:'Récupérer le flag sur le bureau admin' },
  ],

  hints:[
    ["Tu ne connais encore personne dans ce domaine. Commence par voir qui y est.",
     "Il existe une commande pour lister tous les comptes du domaine — cherche du côté de `net user`.",
     "Commence par lister les comptes du domaine : `net user /domain`"],
    ["Un des comptes du domaine n'est pas un vrai humain : c'est un compte de service. Ça se voit à son nom.",
     "Regarde les détails du compte qui commence par svc_, ou cherche une commande qui liste directement les comptes avec un SPN.",
     "Un des comptes ressemble à un compte de service (préfixe svc_). Regarde ses détails avec `net user svc_backup /domain`, ou liste directement les comptes vulnérables avec `get-domainuser -spn`."],
    ["Tout compte avec un SPN peut se voir demander un ticket Kerberos, même par un utilisateur standard comme toi.",
     "Il existe une commande pour réclamer ce ticket — cherche du côté de `invoke-kerberoast`.",
     "Une fois le compte identifié, demande son ticket Kerberos avec `invoke-kerberoast -identity svc_backup`"],
    ["Le ticket que tu as obtenu est chiffré avec le mot de passe du compte. Rien ne t'empêche d'essayer de le casser hors-ligne.",
     "Il existe une commande `crack` qui prend ce hash en argument.",
     "Le ticket obtenu est un hash. Essaie de le cracker avec `crack <hash>`"],
    ["Tu connais maintenant un mot de passe en clair. Rien ne t'empêche de t'en servir.",
     "Il existe une commande Windows pour ouvrir une session avec une identité qui n'est pas la tienne.",
     "Une fois le mot de passe en clair, ouvre une session avec `runas /user:svc_backup cmd`"],
    ["Le compte que tu contrôles appartient à un groupe qui a des droits particuliers sur les fichiers.",
     "Ce groupe peut lire n'importe quel fichier, y compris ceux d'un autre bureau. Regarde ce qu'il y a sur celui de l'administrateur.",
     "Le compte svc_backup appartient au groupe Backup Operators, qui peut lire n'importe quel fichier. Regarde le bureau de l'administrateur avec `dir` puis `type flag.txt`."]
  ],

  manPages:{
    'net': { name:'net user', role:"Interroge les comptes du domaine (comme un annuaire d'entreprise)",
      explain:"Sans argument après /domain, liste tous les comptes. Avec un nom, affiche les détails d'un compte précis : description, groupes, et parfois un SPN.",
      usage:'net user /domain   |   net user <nom> /domain' },
    'get-domainuser': { name:'get-domainuser -spn', role:'Liste les comptes vulnérables au Kerberoasting',
      explain:"Un SPN (Service Principal Name) associe un service à un compte. Tout compte avec un SPN peut se voir demander un ticket Kerberos par n'importe quel utilisateur authentifié — même standard.",
      usage:'get-domainuser -spn' },
    'invoke-kerberoast': { name:'invoke-kerberoast', role:'Demande le ticket Kerberos chiffré d\'un compte de service',
      explain:"Le ticket est chiffré avec le mot de passe du compte de service. Tu peux le récupérer légitimement (le protocole Kerberos le permet à tout utilisateur), puis tenter de le casser hors-ligne, sans alerter personne.",
      usage:'invoke-kerberoast -identity <nom>' },
    'crack': { name:'crack', role:'Casse un ticket Kerberos hors-ligne pour retrouver le mot de passe',
      explain:"Si le mot de passe du compte de service est faible ou commun, un dictionnaire de mots de passe suffit à le retrouver à partir du ticket chiffré.",
      usage:'crack <hash>' },
    'runas': { name:'runas /user', role:"Ouvre une session avec un autre compte",
      explain:"Une fois le mot de passe en clair obtenu, tu peux te reconnecter avec l'identité (et donc les droits) de ce compte.",
      usage:'runas /user:<nom> cmd' }
  },

  knownCommands:[
    'help','clear','man ','whoami /priv',
    'net user /domain','net user ','get-domainuser -spn',
    'invoke-kerberoast -identity ','crack ','runas /user:','dir','type '
  ],

  helpLine:'whoami /priv, net user /domain, net user &lt;nom&gt; /domain, get-domainuser -spn, invoke-kerberoast -identity &lt;nom&gt;, crack &lt;hash&gt;, runas /user:&lt;nom&gt; cmd, dir, type &lt;fichier&gt;, clear',

  cmdRefHtml:`whoami /priv<br>net user /domain<br>net user &lt;nom&gt; /domain<br>get-domainuser -spn<br>invoke-kerberoast -identity &lt;nom&gt;<br>crack &lt;hash&gt;<br>runas /user:&lt;nom&gt; cmd<br>dir<br>type &lt;fichier&gt;<br>help`,

  introLines:[
    `<span class="out-dim">Microsoft Windows [Simulation AD Lab]</span>`,
    `<span class="out-dim">Session ouverte en tant que CORP\\j.dupont sur WKS-042</span>`,
    `<span class="out-info">Tape <b>help</b> pour voir les commandes disponibles.</span>`
  ],

  lessonSlides:[
    { icon:'🏰', title:"Qu'est-ce qu'un domaine Active Directory ?", html:
      `<p>Dans une entreprise, chaque utilisateur, chaque machine, chaque droit d'accès est géré depuis un point central : le <b>contrôleur de domaine</b>. C'est l'annuaire qui dit "qui a le droit de faire quoi".</p>
       <p>Le vrai objectif d'un attaquant, c'est de <b>remonter</b> depuis un compte à faibles privilèges jusqu'à un compte avec les pleins pouvoirs sur le domaine — un <b>Domain Admin</b>. C'est la couronne.</p>` },
    { icon:'🎟️', title:'Kerberos & le SPN', html:
      `<p><b>Kerberos</b> est le protocole d'authentification d'Active Directory : au lieu d'envoyer un mot de passe à chaque service, tu obtiens des "tickets" qui prouvent ton identité.</p>
       <p>Un <b>SPN</b> relie un service à un compte du domaine. Point important : <b>n'importe quel utilisateur authentifié</b>, même standard, peut légitimement demander un ticket pour un compte qui a un SPN.</p>` },
    { icon:'🔓', title:'L\'attaque : Kerberoasting', html:
      `<p>Le ticket obtenu pour un compte de service est <b>chiffré avec le mot de passe de ce compte</b>. Tu peux l'emporter et le casser hors-ligne, tranquillement.</p>
       <p>Si ce mot de passe est faible, tu le retrouves en clair. Résultat : tu deviens ce compte — et ses droits deviennent les tiens.</p>` },
    { icon:'📋', title:'Ta mission', html:
      `<p>Tu es <b>CORP\\j.dupont</b>, employé standard sur le domaine <b>CORP.LOCAL</b>. Trouve un compte de service vulnérable, obtiens son mot de passe, et vois jusqu'où ses droits te mènent.</p>
       <p class="lesson-tip">💡 Tape <b>help</b> une fois dans le terminal, ou <b>man &lt;commande&gt;</b> pour comprendre une commande précise.</p>` }
  ],

  completeTitle:'Domaine compromis',
  completeSub:'Compte de service exploité, groupe privilégié abusé.',
  chainSteps:[
    {icon:'🔎', label:'Énumération'}, {icon:'🎟️', label:'SPN trouvé'},
    {icon:'🔓', label:'Kerberoast'}, {icon:'🗝️', label:'Crack'}, {icon:'👑', label:'Flag'}
  ],
  flag:'FLAG{kerberoast_svc_backup_operators}',

  // Carte d'attaque (façon BloodHound) : vérité terrain, révélée progressivement.
  graph:{
    nodes:[
      { id:'j.dupont', label:'j.dupont', type:'user' },
      { id:'a.martin', label:'a.martin', type:'admin' },
      { id:'svc_backup', label:'svc_backup', type:'service' },
      { id:'administrator', label:'administrator', type:'admin' },
      { id:'grp_backupops', label:'Backup Operators', type:'group' }
    ],
    edges:[
      { id:'e_member', from:'svc_backup', to:'grp_backupops', type:'memberof', label:'MemberOf' },
      { id:'e_bypass', from:'grp_backupops', to:'administrator', type:'abuse', label:'Lecture fichiers (bypass ACL)' },
      { id:'e_owned', from:'j.dupont', to:'svc_backup', type:'owned', label:'Kerberoast + crack' }
    ]
  },

  // Défenseur vivant : dès que le bruit cumulé atteint ce seuil (typiquement juste après
  // la demande de ticket, l'action la plus bruyante de la chaîne), le SOC simulé réagit
  // pour de vrai — pas juste une jauge qui monte. Ici la réaction est réaliste ET ne casse
  // pas la mission : le ticket déjà obtenu reste chiffré avec l'ANCIEN mot de passe, donc
  // toujours cassable. C'est justement la leçon : une rotation après coup arrive trop tard.
  opsecReaction:{
    threshold:20,
    message:"un volume anormal de requêtes LDAP/Kerberos sur svc_backup déclenche une rotation automatique de son mot de passe. Mais le ticket que tu as déjà en main reste chiffré avec l'ANCIEN mot de passe : une fois obtenu, il n'y a plus de fenêtre à rater — trop tard pour cette réaction-là."
  },

  counterMeasure:{
    label:'Comptes de service gérés (gMSA)',
    briefing:"🛡️ Contre-mesure appliquée : SVC-BACKUP a été migré vers un compte de service géré (gMSA). Son mot de passe fait désormais 240 caractères aléatoires et tourne automatiquement toutes les 30 heures."
  },
  deepDive:{
    mitre:[{id:'T1558.003', name:"Steal or Forge Kerberos Tickets: Kerberoasting"}],
    why:"Le protocole Kerberos autorise, par conception, tout utilisateur authentifié à demander un ticket de service pour n'importe quel compte possédant un SPN. Ce n'est pas une faille du protocole — c'est son fonctionnement normal. Le seul maillon faible est la robustesse du mot de passe qui chiffre ce ticket.",
    defenses:[
      "Utiliser des comptes de service gérés (gMSA) : mot de passe long, aléatoire, changé automatiquement par AD",
      "Si un compte de service classique est indispensable, imposer un mot de passe de 25+ caractères aléatoires",
      "Surveiller les demandes de tickets de service inhabituelles (Event ID 4769 côté Windows)",
      "Limiter les comptes de service à des groupes à faible privilège quand c'est possible"
    ],
    quiz:[
      { q:"Pourquoi un utilisateur standard peut-il demander le ticket Kerberos d'un compte de service ?",
        options:["C'est une faille du protocole Kerberos","C'est le fonctionnement normal de Kerberos pour tout compte avec un SPN","Il faut d'abord être administrateur du domaine","Le compte de service a mal configuré ses ACL"],
        correct:1,
        explain:"Kerberos est conçu ainsi : tout utilisateur authentifié peut demander un ticket de service pour n'importe quel SPN. La seule protection réelle est la robustesse du mot de passe qui chiffre ce ticket." },
      { q:"Quelle mesure réduit le plus efficacement le risque de Kerberoasting ?",
        options:["Changer le mot de passe de l'utilisateur standard","Utiliser des comptes de service gérés (gMSA)","Désactiver le compte administrateur intégré","Chiffrer le disque du contrôleur de domaine"],
        correct:1,
        explain:"Un gMSA a un mot de passe long, aléatoire, et changé automatiquement par AD — il devient donc pratiquement impossible à casser hors-ligne." },
      { q:"Quel Event ID Windows permet de repérer une demande de ticket de service suspecte ?",
        options:["4624","4769","4886","4662"],
        correct:1,
        explain:"L'Event ID 4769 correspond à une demande de ticket de service Kerberos (TGS) — une activité normale en soi, mais anormale en volume ou sur un compte à SPN sensible." }
    ]
  },

  initState(){ return { crackedHashes:{} }; },

  // Retourne true si la commande a été traitée (le moteur générique s'arrête alors).
  handle(lower, cmd, m){
    const sc = SCENARIOS.kerberoast;

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
      if(u.spn){
        print(`<span class="out-warn">ServicePrincipalName : ${u.spn}</span>`);
        print(`<span class="out-warn">⚠ Ce compte possède un SPN : potentiellement vulnérable au Kerberoasting.</span>`);
        AttackGraph.reveal({ nodes:['grp_backupops'], edges:['e_member'], tags:{ svc_backup:'spn' } });
        complete('spn');
      }
      return true;
    }

    if(lower === 'get-domainuser -spn' || lower === 'getdomainuser -spn'){
      print(`<span class="out-info">Comptes avec un SPN (Kerberoastables) :</span>`);
      let found = false;
      Object.entries(sc.identities).forEach(([name,u])=>{
        if(u.spn){ print(`<span class="out-warn">  ${name}  —  ${u.spn}</span>`); found = true; }
      });
      if(!found) print(`<span class="out-dim">  (aucun)</span>`);
      AttackGraph.reveal({ nodes:['grp_backupops'], edges:['e_member'], tags:{ svc_backup:'spn' } });
      complete('spn');
      return true;
    }

    m = lower.match(/^invoke-kerberoast -identity (\S+)$/);
    if(m){
      const name = m[1];
      const u = sc.identities[name];
      if(!u || !u.spn){ print(`<span class="out-bad">Aucun ticket Kerberos disponible pour ce compte.</span>`); return true; }
      print(`<span class="out-info">Ticket TGS demandé pour ${name}...</span>`);
      print(`<span class="out-good">Ticket obtenu :</span>`);
      print(`<span class="out-dim">${u.hash}</span>`);
      complete('kerberoast');
      return true;
    }

    m = lower.match(/^crack (.+)$/) || lower.match(/^hashcat (.+)$/);
    if(m){
      if(state.mitigationApplied){
        print(`<span class="out-bad">Échec du crack : aucune attaque par dictionnaire ni par force brute ne fonctionne sur ce mot de passe.</span>`);
        print(`<span class="out-dim">💡 Le ticket Kerberoasté est toujours récupérable — mais SVC-BACKUP est maintenant un gMSA : 240 caractères aléatoires, régénérés automatiquement. Rien à casser.</span>`);
        return true;
      }
      const svc = sc.identities['svc_backup'];
      print(`<span class="out-info">Tentative de crack du ticket (dictionnaire)...</span>`);
      print(`<span class="out-good">Mot de passe trouvé : ${svc.crackedPassword}</span>`);
      state.extra.crackedHashes['svc_backup'] = svc.crackedPassword;
      AttackGraph.reveal({ tags:{ svc_backup:'cracked' } });
      complete('crack');
      return true;
    }

    m = lower.match(/^runas \/user:(\S+) cmd$/);
    if(m){
      const name = m[1];
      if(name === 'svc_backup' && !state.extra.crackedHashes['svc_backup']){
        print(`<span class="out-bad">Mot de passe requis. Crack le ticket d'abord.</span>`);
        return true;
      }
      if(!sc.identities[name]){ print(`<span class="out-bad">Compte introuvable.</span>`); return true; }
      state.user = name;
      updatePrompt();
      print(`<span class="out-good">Nouvelle session ouverte en tant que ${sc.identities[name].label}</span>`);
      AttackGraph.reveal({ edges:['e_owned'] });
      AttackGraph.markOwned(name);
      complete('access');
      return true;
    }

    if(lower === 'dir'){
      if(state.user === 'svc_backup'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\Administrator\\Desktop</span>`);
        print(`<span class="out-dim">  [droits Backup Operators : lecture autorisée malgré les ACL]</span>`);
        print(`<span class="out-dim">  flag.txt</span>`);
        AttackGraph.reveal({ edges:['e_bypass'] });
      } else if(state.user === 'j.dupont'){
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  notes.txt</span>`);
        print(`<span class="out-dim">💡 Ce dossier t'appartient. Pour voir le bureau de l'administrateur, il te faudra un compte avec plus de droits.</span>`);
      } else {
        print(`<span class="out-info"> Répertoire : C:\\Users\\${state.user}\\Desktop</span>`);
        print(`<span class="out-dim">  (vide)</span>`);
      }
      return true;
    }

    if(lower.startsWith('type ')){
      const file = cmd.slice(5).trim();
      if(file.toLowerCase() === 'flag.txt' && state.user === 'svc_backup'){
        print(`<span class="flag-tag">${sc.flag}</span> <button class="copy-btn" onclick="copyFlag(this)">📋 Copier</button>`);
        print(`<span class="out-good">🎉 Bravo — chaîne complète : énumération → Kerberoasting → crack → abus du groupe Backup Operators.</span>`);
        print(`<span class="out-dim">🛡️ Pour se défendre : mots de passe de service longs/aléatoires (idéalement un gMSA géré automatiquement), et surveiller les demandes de tickets suspectes.</span>`);
        AttackGraph.markOwned('administrator');
        complete('flag');
        finishMission();
      } else if(file.toLowerCase() === 'flag.txt'){
        print(`<span class="out-bad">Accès refusé : ton compte (${state.user}) n'a pas les droits de lecture sur ce fichier.</span>`);
        print(`<span class="out-dim">💡 Le bureau de l'administrateur est protégé. Il te faut un compte membre d'un groupe qui contourne cette restriction.</span>`);
      } else if(file.toLowerCase() === 'notes.txt'){
        print(`<span class="out-dim">"Penser à changer le mdp de svc_backup un jour..." — j.dupont</span>`);
      } else {
        print(`<span class="out-bad">Fichier introuvable : ${escapeHtml(file)}</span>`);
      }
      return true;
    }

    return false;
  }
};
